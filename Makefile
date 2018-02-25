CC = g++
CFLAGS = -Wall -Wextra -ggdb3
LDFLAGS = -lcapstone

all: ded

ded: main.o mz_exe.o core.o options.o
	${CC} ${CFLAGS} $^ -o $@ ${LDFLAGS}

%.o: %.cpp
	${CC} ${CFLAGS} -c $^ -o $@

.PHONY: clean
clean:
	rm -f *.o ded
