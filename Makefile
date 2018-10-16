CFLAGS := -Wall -Wextra -Werror

all: ldbserver test

ldbserver: ldbserver.c
	$(CC) $(CFLAGS) $^ -o $@ -ldl -lb64 -ljansson

test: test.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	$(RM) ldbserver test
