CFLAGS=-Wall -D_GNU_SOURCE -lpthread

PROGRAM=locktest
SRC=locktest.c

ALL: $(PROGRAM)

$(PROGRAM): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LIB_OBJS) -g -o $@

archive: tar bzip xz

tar:
	git archive --format=tar --prefix=test-discard/ HEAD -o $(PROGRAM).tar

bzip:
	bzip2 $(PROGRAM).tar

xz:
	xz $(PROGRAM).tar


clean:
	rm -rf *.o $(PROGRAM)
