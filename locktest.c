/* SPDX-License-Identifier: GPL-2.0 */ 
/*
 * Simple test program for stress testing atomic bit operations and
 * locking. Some of the code borrowed from linux kernel code
 *
 * Author: Lukas Czerner <lczerner at redhat dot com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <asm/types.h>
#include <time.h>
#include <sched.h>
#include <stdbool.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <signal.h>


/*
 * All atomic functions and locking primitives copied over
 * from linux kernel sources
 */

#define BITS_PER_LONG	64
#define BIT_WORD(nr)	((nr) / BITS_PER_LONG)
#define BIT_MASK(nr)	((unsigned long) 1 << ((nr) % BITS_PER_LONG))


#define LOCK_PREFIX_HERE \
		".pushsection .smp_locks,\"a\"\n"	\
		".balign 4\n"				\
		".long 671f - .\n" /* offset */		\
		".popsection\n"				\
		"671:"
#define LOCK_PREFIX LOCK_PREFIX_HERE "\n\tlock; "

#define __READ_ONCE(x)	(*(const volatile typeof(x) *)&(x))

typedef struct {
	__s64 counter;
} atomic64_t;

static inline void atomic64_or(__s64 i, atomic64_t *v)
{
	asm volatile(LOCK_PREFIX "orq %1,%0"
			: "+m" (v->counter)
			: "er" (i)
			: "memory");
}

static inline void atomic64_and(__s64 i, atomic64_t *v)
{
		asm volatile(LOCK_PREFIX "andq %1,%0"
		: "+m" (v->counter)
		: "er" (i)
		: "memory");
}

#ifdef __GCC_ASM_FLAG_OUTPUTS__
# define CC_SET(c) "\n\t/* output condition code " #c "*/\n"
# define CC_OUT(c) "=@cc" #c
#else
# define CC_SET(c) "\n\tset" #c " %[_cc_" #c "]\n"
# define CC_OUT(c) [_cc_ ## c] "=qm"
#endif

#define __raw_try_cmpxchg(_ptr, _pold, _new, size, lock)		\
({									\
	bool success;							\
	__typeof__(_ptr) _old = (__typeof__(_ptr))(_pold);		\
	__typeof__(*(_ptr)) __old = *_old;				\
	__typeof__(*(_ptr)) __new = (_new);				\
	volatile __u64 *__ptr = (volatile __u64 *)(_ptr);		\
	asm volatile(lock "cmpxchgq %[new], %[ptr]"		\
		     CC_SET(z)					\
		     : CC_OUT(z) (success),			\
		       [ptr] "+m" (*__ptr),			\
		       [old] "+a" (__old)			\
		     : [new] "r" (__new)			\
		     : "memory");				\
	if (!success)						\
		*_old = __old;						\
	(success);						\
})

#define __try_cmpxchg(ptr, pold, new, size)				\
	__raw_try_cmpxchg((ptr), (pold), (new), (size), LOCK_PREFIX)

#define try_cmpxchg(ptr, pold, new) 					\
	__try_cmpxchg((ptr), (pold), (new), sizeof(*(ptr)))


static __always_inline bool arch_atomic64_try_cmpxchg(atomic64_t *v, __s64 *old, __s64 new)
{
	return try_cmpxchg(&v->counter, old, new);
}

static inline __s64 arch_atomic64_fetch_or(__s64 i, atomic64_t *v)
{
	__s64 val = __READ_ONCE((v)->counter);

	do {
	} while (!arch_atomic64_try_cmpxchg(v, &val, val | i));
	return val;
}

static inline __s64 arch_atomic64_fetch_and(__s64 i, atomic64_t *v)
{
	__s64 val = __READ_ONCE((v)->counter);

	do {
	} while (!arch_atomic64_try_cmpxchg(v, &val, val & i));
	return val;
}

static inline int test_bit(int nr, const volatile unsigned long *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
}

static inline void set_bit(unsigned int nr, volatile unsigned long *p)
{
	p += BIT_WORD(nr);
	atomic64_or(BIT_MASK(nr), (atomic64_t *)p);
}

static inline void clear_bit(unsigned int nr, volatile unsigned long *p)
{
	p += BIT_WORD(nr);
	atomic64_and(~BIT_MASK(nr), (atomic64_t *)p);
}

static inline int test_and_set_bit_lock(unsigned int nr,
					volatile unsigned long *p)
{
	long old;
	unsigned long mask = BIT_MASK(nr);

	p += BIT_WORD(nr);

	old = arch_atomic64_fetch_or((__s64)mask, (atomic64_t *)p);
	return !!(old & mask);
}

static inline void bit_spin_lock(int bitnum, unsigned long *addr)
{

	while (test_and_set_bit_lock(bitnum, addr)) {
		do {
			sched_yield();
		} while (test_bit(bitnum, addr));
	}
}

static inline void bit_spin_unlock(unsigned int nr, volatile unsigned long *p)
{
	p += BIT_WORD(nr);
	arch_atomic64_fetch_and(~BIT_MASK(nr), (atomic64_t *)p);
}


#define handle_error_en(en, msg) \
	do { errno = en; perror(msg); goto out_free; } while (0)

#define handle_error(msg) \
	do { perror(msg); goto out_free; } while (0)

#define LOCK_BIT	22
#define RUNNING		0
#define STOPPED		1

struct process_config {
	struct buffer_head *bh;		/* test struct for lock and bitops */
	struct journal_head *jh;	/* test struct for refcount */

	int num_ref_threads;	/* Number of refcount threads to create */
	int num_bit_threads;	/* Number of bitops threads to create */

	int ref_delay_mult;	/* Refcount delay multiplier */
	int bit_delay_mult;	/* Bitops delay multiplier */

	pid_t pid;		/* PID if running multiple processes */

	struct thread_info *ref_tinfo;	/* Refcount thread info */
	struct thread_info *bit_tinfo;	/* Bitops thread info */

	int run_time;		/* Number of second to run threads for */
	int ret;		/* Return value for the process */
	int nprocs;		/* Number of processes */
};

struct thread_info {
	pthread_t thread_id;
	unsigned int thread_num;
	unsigned long n_operations;
	struct process_config *pc;
};

/*
 * Dummy buffer_head copied from kernel just in case
 * the structure layout matters
 */
struct buffer_head {
	unsigned long b_state;
	void *b_this_page;
	void *b_page;
	__u64 b_blocknr;
	size_t b_size;
	char *b_data;
	void *b_bdev;
	void *b_end_io;
 	void *b_private;
	void *b_assoc_buffers;
	void *b_assoc_map;
	atomic64_t b_count;
	atomic64_t b_uptodate_lock;
};

/*
 * Dummy journal_head copied from kernel just in case
 * the structure layout matters
 */
struct journal_head {
	struct buffer_head *b_bh;
	atomic64_t b_state_lock;
	unsigned b_jlist;
	unsigned b_modified;
	char *b_frozen_data;
	char *b_committed_data;
	void *b_transaction;
	void *b_next_transaction;
	void *b_tnext, *b_tprev;
	void *b_cp_transaction;
	void *b_cpnext, *b_cpprev;
	void *b_triggers;
	void *b_frozen_triggers;
	int pad[8];
	int b_jcount;
};

#define RANDOM_MULT	9763541  /* prime */
#define RANDOM_ADD	1076769773 /* prime */
#define RANDOM_REFRESH	10000

unsigned long loops_in_us;		/* How many loops in us */
static volatile sig_atomic_t status;	/* Status to control threads */

struct random_state {
	unsigned long state;
	long count;
};
#define DEFINE_RANDOM(name) struct random_state name = { 0, 0 }

/*
 * Very basic linear congruential random generator based on the
 * code in kernel/torture.c
 */
unsigned long rnd(struct random_state *rs)
{
	if (--rs->count < 0) {
		rs->state += (unsigned long)rand();
		rs->count = RANDOM_REFRESH;
	}
	rs->state = rs->state * RANDOM_MULT + RANDOM_ADD;
	return rs->state;
}


static __always_inline void delay_loop(__u64 __loops)
{
	unsigned long loops = (unsigned long)__loops;

	asm volatile(
		"	test %0,%0	\n"
		"	jz 3f		\n"
		"	jmp 1f		\n"

		".align 16		\n"
		"1:	jmp 2f		\n"

		".align 16		\n"
		"2:	dec %0		\n"
		"	jnz 2b		\n"
		"3:	dec %0		\n"

		: /* we don't need output */
		:"a" (loops)
	);
}

static inline void delay_us(int us)
{
	delay_loop(loops_in_us * us);
}

/*
 * Get some rough idea of how many loops can we do
 * in micro second
 */
static void measure_delay(void)
{
	unsigned long loops = 100 * 4096;
	struct timespec t1, t2;

	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1);
	delay_loop(loops);
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t2);

	loops_in_us = loops / ((t2.tv_nsec - t1.tv_nsec) / 1000);
}

static inline void delay(struct random_state *rs, int threads, int mult) {
	int shortdelay_us = 2 * mult;
	int longdelay_us = 100 * 1000 * mult;

	if (mult == 0)
		return;

	/*
	 * Short delay to emulate code and occasional long delay
	 * to emulate longer stalls
	 */
	if (!(rnd(rs) % (threads * 2000 * longdelay_us)))
		delay_us(longdelay_us);
	if (!(rnd(rs) % (threads * 2 * shortdelay_us)))
		delay_us(shortdelay_us);
}


static void test_failed(struct process_config *pc)
{
	printf("(PID:%d) TEST FAILED: b_jcount must be at least 1 but "
	       "is %d !!\n", pc->pid, pc->jh->b_jcount);
	pc->ret = EXIT_FAILURE;
	status = STOPPED;
	kill(getppid(), SIGINT);
}

static inline void maybe_yield(int threads)
{
	if (!(rand() % (threads * 100)))
		sched_yield();
}

/*
 * Function to do the refcounting under
 * the lock
 */
static void *thread_refcount(void *arg)
{
	struct thread_info *tinfo = arg;
	struct process_config *pc = tinfo->pc;
	struct buffer_head *bh = pc->bh;
	struct journal_head *jh = pc->jh;
	DEFINE_RANDOM(rrs);

	do {
		maybe_yield(pc->num_ref_threads);

		bit_spin_lock(LOCK_BIT, &bh->b_state);
		if (jh->b_jcount <= 0) {
			test_failed(pc);
			bit_spin_unlock(LOCK_BIT, &bh->b_state);
			break;
		}
		jh->b_jcount++;
		tinfo->n_operations++;
		delay(&rrs, pc->num_ref_threads, pc->ref_delay_mult);
		bit_spin_unlock(LOCK_BIT, &bh->b_state);

		maybe_yield(pc->num_ref_threads);
		
		bit_spin_lock(LOCK_BIT, &bh->b_state);
		--jh->b_jcount;
		if (jh->b_jcount <= 0) {
			test_failed(pc);
			bit_spin_unlock(LOCK_BIT, &bh->b_state);
			break;
		}
		tinfo->n_operations++;
		delay(&rrs, pc->num_ref_threads, pc->ref_delay_mult);
		bit_spin_unlock(LOCK_BIT, &bh->b_state);

	} while (status == RUNNING);

	return NULL;
}

/*
 * Function to do set_bit/clear_bit in the loop
 * with delays in between
 */
static void *thread_bitops(void *arg)
{
	struct thread_info *tinfo = arg;
	struct process_config *pc = tinfo->pc;
	struct buffer_head *bh = pc->bh;
	int nr;
	DEFINE_RANDOM(brs);

	do {
		delay(&brs, pc->num_bit_threads, pc->bit_delay_mult);
		nr = rand() % 64;
		if (nr == LOCK_BIT)
			nr--;
		set_bit(nr, &bh->b_state);
		
		maybe_yield(pc->num_bit_threads);

		tinfo->n_operations++;
		delay(&brs, pc->num_bit_threads, pc->bit_delay_mult);

		clear_bit(nr, &bh->b_state);
		
	} while (status == RUNNING);

	return NULL;
}

static void print_stats(struct thread_info *tinfo, int threads,
			pid_t pid, bool ref)
{
	int i;
	unsigned long max, min;
	unsigned long long sum = 0;

	if (threads == 0)
		return;

	max = 0;
	min = tinfo[0].n_operations;

	for (i = 0; i < threads; i++) {
		sum += tinfo[i].n_operations;
		if (tinfo[i].n_operations > max)
			max = tinfo[i].n_operations;
		if (tinfo[i].n_operations < min)
			min = tinfo[i].n_operations;
	}

	fprintf(stdout, "(PID:%d) %d %s threads: Total: %llu Max/Min: "
			"%lu/%lu\n", pid,
			threads, ref ? "refcounting" : "set_bit/clear_bit",
			sum, max, min);
}

static inline void print_usage(char *progname) {
	fprintf(stderr, "Usage: %s -t SEC [-r NUM] [-b NUM] [-d NULT] [-D MULT]\n"
			"  -h\tPrint this help\n"
			"  -s\tPrint stats at the end of the run\n"
			"  -r\tNumber of refcounting threads (default:cpu count)\n"
			"  -b\tNumber of bitops threads (default:cpu count / 4)\n"
			"  -d\tBitops delay multiplier (default:1, 0 - disable)\n"
			"  -D\tRefcount delay multiplier (default:1, 0 - disable)\n"
			"  -t\tRun time duration in seconds (default:60)\n\n"
			"  -p\rNumber of instances of locktest to run in "
			"parallel (default: cpu count / 5)"
			"At least one process and one refcounting, or bitops "
			"thread must be set Run time duration must be set.\n"
			"Example: %s -r100 -b20 -t60\n", progname, progname);
}

static void stop_threads(int signal) {
	status = STOPPED;
}

/* Parent controlling the processes */
static int parent(struct process_config *pc) {
	int s, err, ret = EXIT_SUCCESS;
	struct sigaction sig;
	pid_t wpid;
	int nprocs = pc->nprocs;

	/* Set up alarm to go off after run_time */
	memset(&sig, 0, sizeof(sig));
	sig.sa_handler = stop_threads;
	if (sigaction(SIGALRM, &sig, 0)) {
		perror("sigaction");
		kill(-getpid(), SIGINT);
		goto wait_loop;
	}
	if (alarm(pc->run_time)) {
		perror("alarm");
		kill(-getpid(), SIGINT);
	}

wait_loop:
	/* Wait for all the processess to finish */
	while (nprocs > 0) {
		wpid = wait(&s);

		/* wait failed or was interrupted */
		if (wpid == -1) {
			if (errno == ECHILD) {
				break;
			} else if (errno == EINTR) {
				kill(-getpid(), SIGINT);
				continue;
			}
		}

		if (WIFEXITED(s)) {
			err = WEXITSTATUS(s);
		} else if (WIFSIGNALED(s)) {
			err = WTERMSIG(s);
		} else if (WIFSTOPPED(s)) {
			err = WSTOPSIG(s);
		}

		if (err)
			ret = err;
		nprocs--;
	}

	/* No errors encountered */
	if (ret == EXIT_SUCCESS)
		fprintf(stdout, "No problems found\n");
	return ret;
}

int main(int argc, char **argv)
{
	int err, tnum, opt, ncpus, id, p, stats;
	struct thread_info *ref_tinfo, *bit_tinfo;
	struct buffer_head *bh;
	struct journal_head *jh;
	struct process_config *pc;
	struct sigaction sig;
	void *res;
	int ret = EXIT_FAILURE;

	pc = calloc(1, sizeof(struct process_config));
	if (pc == NULL)
		handle_error("calloc");

	/* Initialize default parameters */
	ncpus = get_nprocs();
	pc->num_ref_threads = ncpus;
	pc->num_bit_threads = (ncpus <= 4) ? 1 : ncpus / 4;
	pc->ref_delay_mult = 1;
	pc->bit_delay_mult = 1;
	pc->run_time = 60;
	status = RUNNING;
	pc->nprocs = (ncpus <= 5) ? 1 : ncpus / 5;
	stats = 0;

	srand(time(NULL));

	/* Get program parameters */
	while ((opt = getopt(argc, argv, "t:r:b:D:d:hp:s")) != -1) {
		switch (opt) {
		case 't':
			pc->run_time = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			pc->num_ref_threads = strtoul(optarg, NULL, 0);
			break;
		case 'b':
			pc->num_bit_threads = strtoul(optarg, NULL, 0);
			break;
		case 'D':
			pc->ref_delay_mult = strtol(optarg, NULL, 0);
			break;
		case 'd':
			pc->bit_delay_mult = strtol(optarg, NULL, 0);
			break;
		case 'p':
			pc->nprocs = strtol(optarg, NULL, 0);
			break;
		case 's':
			stats = 1;
			break;
		case 'h':
			print_usage(argv[0]);
			return EXIT_SUCCESS;
		default:
			print_usage(argv[0]);
			return EXIT_FAILURE;
		}
	}

	/* Run time must be set */
	if (!pc->run_time) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* At least some threads must be set */
	if (!pc->num_ref_threads && !pc->num_bit_threads) {
		fprintf(stderr, "Some number threads must be set!\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* At least 1 process must be created */
	if (!pc->nprocs) {
		fprintf(stderr, "Number of processes can't be zero\n");
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	/* Measure the number of loops needed for us delay */
	measure_delay();

	/*
	 * Set the initial state to zero, it needs to be zero after
	 * were finished, otherwise set_bit/clear_bit are not atomic
	 */
	bh = malloc(sizeof(struct buffer_head));
	if (bh == NULL)
		handle_error("malloc");
	bh->b_state = 0;
	pc->bh = bh;

	/*
	 * Set the initial reference to 1, it needs to be 1 after
	 * we're finished, otherwise locking does not work
	 */
	jh = malloc(sizeof(struct journal_head));
	if (jh == NULL)
		handle_error("malloc");
	jh->b_jcount = 1;
	pc->jh = jh;
	
	/* Refcointing thread info */
	ref_tinfo = calloc(pc->num_ref_threads, sizeof(struct thread_info));
	if (ref_tinfo == NULL)
		handle_error("calloc");

	/* Bitops thread info */
	bit_tinfo = calloc(pc->num_bit_threads, sizeof(struct thread_info));
	if (bit_tinfo == NULL)
		handle_error("calloc");

	fprintf(stdout, "Running %d instances of locktest with %d "
			"recounting and %d bitops threads for %d seconds\n",
			pc->nprocs, pc->num_ref_threads,
			pc->num_bit_threads, pc->run_time);

	/* Setup a handler for the SIGINT to stop all threads*/
	memset(&sig, 0, sizeof(sig));
	sig.sa_handler = stop_threads;
	if (sigaction(SIGINT, &sig, 0)) {
		handle_error("signal");
	}

	/* Spawn nprocs processes */
	for(p = 0; p < pc->nprocs; p++) {
		id = fork();
		if (id < 0)
			perror("fork");
		else if (id == 0) {
			pc->pid = getpid();
			break;
		}
	}

	/* Parent process ends up here*/
	if (id > 0) {
		ret = parent(pc);
		goto out_free;
	}

	/* Create refcounting threads */
	for (tnum = 0; tnum < pc->num_ref_threads; tnum++) {
		ref_tinfo[tnum].thread_num = tnum;
		ref_tinfo[tnum].pc = pc;

		err = pthread_create(&ref_tinfo[tnum].thread_id, NULL,
				   &thread_refcount, &ref_tinfo[tnum]);
		if (err != 0)
			handle_error_en(err, "pthread_create");
	}

	/* Create set_bit/clear_bit threads */
	for (tnum = 0; tnum <  pc->num_bit_threads; tnum++) {
		bit_tinfo[tnum].thread_num = tnum;
		bit_tinfo[tnum].pc = pc;

		err = pthread_create(&bit_tinfo[tnum].thread_id, NULL,
				   &thread_bitops, &bit_tinfo[tnum]);
		if (err != 0)
			handle_error_en(err, "pthread_create");
	}

	/* Wait for refcounting threads to finish */
	for (tnum = 0; tnum < pc->num_bit_threads; tnum++) {
		err = pthread_join(bit_tinfo[tnum].thread_id, &res);
		if (err != 0)
			handle_error_en(err, "pthread_join");
	}

	/* Wait for set_bit/clear_bit threads to finish */
	for (tnum = 0; tnum < pc->num_ref_threads; tnum++) {
		err = pthread_join(ref_tinfo[tnum].thread_id, &res);
		if (err != 0)
			handle_error_en(err, "pthread_join");
	}

	/* Some threads might have failed already */
	if (pc->ret)
		return pc->ret;

	/* b_state must be 0 */
	if (bh->b_state != 0) {
		fprintf(stdout, "(PID:%d) TEST FAILED: b_state must be 0 "
			"but is 0x%08lx (b_jcount = %d)\n",
			pc->pid, bh->b_state, jh->b_jcount);
		goto out_free;
	}

	/* b_jcount must be 1 */
	if (jh->b_jcount != 1) {
		fprintf(stdout, "(PID:%d) TEST FAILED: b_jcount must be 1 "
			"but is %d (b_state = 0x%08lx)\n",
			pc->pid, jh->b_jcount, bh->b_state);
		goto out_free;
	}

	/* Print stats if requested */
	if (stats) {
		print_stats(ref_tinfo, pc->num_ref_threads, pc->pid, true);
		print_stats(bit_tinfo, pc->num_bit_threads, pc->pid, false);
	}
	ret = EXIT_SUCCESS;

out_free:
	/* Free all memory and exit */
	if (ref_tinfo)
		free(ref_tinfo);
	if (bit_tinfo)
		free(bit_tinfo);
	if (bh)
		free(bh);
	if (jh)
		free(jh);
	if (pc)
		free(pc);

	return ret;
}
