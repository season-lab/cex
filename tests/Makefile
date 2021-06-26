SRCS      = $(wildcard *.c)
SRCS_CPP  = $(wildcard *.cpp)
PROGS     = $(patsubst %.c,%,$(SRCS))
PROGS_CPP = $(patsubst %.cpp,%,$(SRCS_CPP))
CFLAGS = -O0

all: $(PROGS) $(PROGS_CPP)

%: %.c
	$(CC) $(CFLAGS) -o $@.elf -L./libs -lfoo $<

%: %.cpp
	$(CXX) $(CFLAGS) -o $@.elf -L./libs -lfoo $<

clean:
	rm -f *.elf
