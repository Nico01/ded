CXX = clang++
CXXFLAGS = -Wall -Wextra -ggdb3
LDFLAGS = -lcapstone

all: ded

ded: main.o core.o options.o binary.o
	${CXX} ${CXXFLAGS} $^ -o $@ ${LDFLAGS}

%.o: %.cpp
	${CXX} ${CXXFLAGS} -c $^ -o $@

.PHONY: clean
clean:
	rm -f *.o ded
