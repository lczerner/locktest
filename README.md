# LOCKTEST

Simple test program for stress testing atomic bit operations and
locking. It is similar in functionality to hacked locktorture module
found here https://github.com/lczerner/linux/tree/jbd2_locktorture.
Some code has been copied from linux kernel.

It contains x86_64 assembly code copied from linux kernel and as such is
only useful for x86_64 architecture.

See the code for details.

## How to build

	make

## Usage

Run the test with default configuration

	./locktest

or modify the parameters as you need

	Usage: ./locktest [-s] [-c SEC] [-t SEC] [-p PROC] [-r NUM] [-b NUM] [-d NULT] [-D MULT]
	  -h	Print this help
	  -s	Print stats at the end of the run
	  -r	Number of refcounting threads (default:cpu count)
	  -b	Number of bitops threads (default:cpu count / 4)
	  -d	Bitops delay multiplier (default:1, 0 - disable)
	  -D	Refcount delay multiplier (default:1, 0 - disable)
	  -t	Run time duration in seconds (default:600)
	  -c	Check interval in secodns (default:random)
	  -p	Number of instances of locktest to run in parallel (default: cpu count / 5)

	At least one process and one refcounting, or bitops thread must be set Run time duration must be set.
	Example: ./locktest -r100 -b20 -t600

## How it works

	jh->b_jcount = 1
	bh->b_state = 0

	Each process runs a specified number of refcounting threads in an infinite
	loop:

	sched_yield()
	bit_spin_lock(LOCK_BIT, &bh->b_state);
	jh->b_jcount++
	delay()
	bit_spin_unlock(LOCK_BIT, &bh->b_state);

	sched_yield()

	bit_spin_lock(LOCK_BIT, &bh->b_state);
	--jh->b_jcount
	delay()
	bit_spin_unlock(LOCK_BIT, &bh->b_state);


	Additionally each process runs a specified number of bitops threads in an
	infinite loop:

	delay()
	nr = pseudorandom_number % 64
	if (nr == LOCK_BIT)
	    nr--
	set_bit(nr, &bh->b_state)

	sched_yield()

	delay()
	clear_bit(nr, &bh->b_state)

	At no point can b_jcount be less then 1. Additionally after the threads are
	stopped the b_jcount must be 1 and b_state must be 0. If any of those
	conditions fail, the test fails.
