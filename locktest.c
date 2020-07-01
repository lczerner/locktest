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
	do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define LOCK_BIT	22
#define RUNNING		0
#define STOPPED		1

struct thread_info {
	pthread_t thread_id;
	unsigned int thread_num;
	unsigned long n_operations;
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

static struct buffer_head *bh;
static struct journal_head *jh;

static int status;			/* Status to control threads */
static int num_ref_threads;		/* Number of refcount threads to create */
static int num_bit_threads;		/* Number of bitops threads to create */

static int ref_delay_mult;
static int bit_delay_mult;

static unsigned long loops_in_us;

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

static inline void delay(int threads, int delay) {
	int shortdelay_us = 2 * delay;
	int longdelay_us = 100 * 1000 * delay;

	if (delay = 0)
		return;

	/*
	 * Short delay to emulate code and occasional long delay
	 * to emulate longer stalls
	 */
	if (!(rand() % (threads * 2000 * longdelay_us)))
		delay_us(longdelay_us);
	if (!(rand() % (threads * 2 * shortdelay_us)))
		delay_us(shortdelay_us);
}


static void test_failed(void) {
	printf("Refcount failed: state = %lu count = %d\n",
		bh->b_state, jh->b_jcount);
	status = STOPPED;
	exit(EXIT_FAILURE);
}

/*
 * Function to do the refcounting under
 * the lock
 */
static void *thread_refcount(void *arg)
{
	struct thread_info *tinfo = arg;

	do {
		sched_yield();

		bit_spin_lock(LOCK_BIT, &bh->b_state);
		if (jh->b_jcount <= 0)
			test_failed();
		jh->b_jcount++;
		tinfo->n_operations++;
		delay(num_ref_threads, ref_delay_mult);
		bit_spin_unlock(LOCK_BIT, &bh->b_state);

		sched_yield();
		
		bit_spin_lock(LOCK_BIT, &bh->b_state);
		--jh->b_jcount;
		if (jh->b_jcount <= 0)
			test_failed();
		tinfo->n_operations++;
		delay(num_ref_threads, ref_delay_mult);
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
	int nr;
	struct thread_info *tinfo = arg;

	do {
		delay(num_bit_threads, bit_delay_mult);
		nr = rand() % 64;
		if (nr == LOCK_BIT)
			nr--;
		set_bit(nr, &bh->b_state);
		
		sched_yield();

		tinfo->n_operations++;
		delay(num_bit_threads, bit_delay_mult);

		clear_bit(nr, &bh->b_state);
		
	} while (status == RUNNING);

	return NULL;
}


static void print_stats(struct thread_info *tinfo, int threads,
			bool ref)
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

	fprintf(stdout, "%d %s threads: Total: %llu Max/Min: %lu/%lu\n", threads,
		 ref ? "refcounting" : "set_bit/clear_bit", sum, max, min);
}

static inline void print_usage(char *progname) {
	fprintf(stderr, "Usage: %s [-r num-refcount-threads] "
			"[-b num-bitops-threads] "
			"[-d bitops-delay-multiplier] "
			"[-D refcount-delay-multiplier] "
			"-t run-time- in-seconds\n", progname);
}


int main(int argc, char **argv)
{
	int s, tnum, opt;
	int run_time = 0;
	struct thread_info *ref_tinfo, *bit_tinfo;
	void *res;

	num_ref_threads = 0;
	num_bit_threads = 0;
	ref_delay_mult = 1;
	bit_delay_mult = 1;
	status = RUNNING;
	srand(time(NULL));

	/* Get program parameters */
	while ((opt = getopt(argc, argv, "t:r:b:D:d:")) != -1) {
		switch (opt) {
		case 't':
			run_time = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			num_ref_threads = strtoul(optarg, NULL, 0);
			break;
		case 'b':
			num_bit_threads = strtoul(optarg, NULL, 0);
			break;
		case 'D':
			ref_delay_mult = strtol(optarg, NULL, 0);
			break;
		case 'd':
			bit_delay_mult = strtol(optarg, NULL, 0);
			break;
		default:
			print_usage(argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	/* Run time must be specified */
	if (!run_time) {
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* At least some threads must be specified */
	if (!num_ref_threads && !num_bit_threads) {
		fprintf(stderr, "Zero threads speficied!\n");
		print_usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	/*
	 * Set the initial state to zero, it needs to be zero after
	 * were finished, otherwise set_bit/clear_bit are not atomic
	 */
	bh = malloc(sizeof(struct buffer_head));
	if (bh == NULL)
		handle_error("malloc");
	bh->b_state = 0;

	/*
	 * Set the initial reference to 1, it needs to be 1 after
	 * we're finished, otherwise locking does not work
	 */
	jh = malloc(sizeof(struct journal_head));
	if (jh == NULL)
		handle_error("malloc");
	jh->b_jcount = 1;
	
	ref_tinfo = calloc(num_ref_threads, sizeof(struct thread_info));
	if (ref_tinfo == NULL)
		handle_error("calloc");

	bit_tinfo = calloc(num_bit_threads, sizeof(struct thread_info));
	if (bit_tinfo == NULL)
		handle_error("calloc");

	measure_delay();

	/* Create refcounting threads */
	for (tnum = 0; tnum < num_ref_threads; tnum++) {
		ref_tinfo[tnum].thread_num = tnum;

		s = pthread_create(&ref_tinfo[tnum].thread_id, NULL,
				   &thread_refcount, &ref_tinfo[tnum]);
		if (s != 0)
			handle_error_en(s, "pthread_create");
	}
	fprintf(stdout, "%d refcounting threads started\n", num_ref_threads);

	/* Create set_bit/clear_bit threads */
	for (tnum = 0; tnum <  num_bit_threads; tnum++) {
		bit_tinfo[tnum].thread_num = tnum;

		s = pthread_create(&bit_tinfo[tnum].thread_id, NULL,
				   &thread_bitops, &bit_tinfo[tnum]);
		if (s != 0)
			handle_error_en(s, "pthread_create");
	}
	fprintf(stdout, "%d set_bit/clear_bit threads started\n", num_bit_threads);
	fprintf(stdout, "Running for %d seconds\n", run_time);

	/* Run the test for specified number of seconds */
	sleep(run_time);

	/* Force the threads to stop */
	status = STOPPED;

	/* Wait for refcounting threads to finish */
	for (tnum = 0; tnum < num_bit_threads; tnum++) {
		s = pthread_join(bit_tinfo[tnum].thread_id, &res);
		if (s != 0)
			handle_error_en(s, "pthread_join");
	}

	/* Wait for set_bit/clear_bit threads to finish */
	for (tnum = 0; tnum < num_ref_threads; tnum++) {
		s = pthread_join(ref_tinfo[tnum].thread_id, &res);
		if (s != 0)
			handle_error_en(s, "pthread_join");
	}

	print_stats(ref_tinfo, num_ref_threads, true);
	print_stats(bit_tinfo, num_bit_threads, false);

	free(ref_tinfo);
	free(bit_tinfo);

	/* state should be 0, check for failure */
	if (bh->b_state != 0) {
		printf("TEST FAILED: state = %lu count = %d\n",
			bh->b_state, jh->b_jcount);
		free(bh);
		free(jh);
		exit(EXIT_FAILURE);
	}

	/* count should be 1, check for failure */
	if (bh->b_state != 0) {
		printf("TEST FAILED: state = %lu count = %d\n",
			bh->b_state, jh->b_jcount);
		free(bh);
		free(jh);
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS: state = %lu count = %d\n",
		bh->b_state, jh->b_jcount);
	free(bh);
	free(jh);
	exit(EXIT_SUCCESS);
}
