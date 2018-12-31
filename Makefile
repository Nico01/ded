CXX = g++
CXXFLAGS = -Wall -Wextra -ggdb3 -std=c++17 -O3
LDFLAGS = -lcapstone -lfmt

all: ded

ded: main.o core.o options.o binary.o analyzer.o disassembler.o utils.o insnfmt.o
	${CXX} ${CXXFLAGS} $^ -o $@ ${LDFLAGS}

%.o: %.cpp
	${CXX} ${CXXFLAGS} -c $^ -o $@

.PHONY: clean
clean:
	rm -f *.o ded
