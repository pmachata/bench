# make CXX=$HOME/opt/gcc48/bin/g++

all: w.so bench

bench: LDFLAGS = -lelf -g
bench: CC = $(CXX)
bench: bench.o

bench.o: CXXFLAGS = -std=c++11 -Wall -g

w.so: w.c
	$(CC) -Wall -fpic -shared -o $@ $<
