CFLAGS = -Wall -Wextra -pedantic -ggdb3
LDFLAGS = -lcapstone

all: ded

ded: main.o core.o
	${CC} ${CFLAGS} $^ -o $@ ${LDFLAGS}

%.o: %.c
	${CC} ${CFLAGS} -c $^ -o $@

.PHONY: clean
clean:
	rm -f *.o ded
