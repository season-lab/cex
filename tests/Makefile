SRCS   = $(wildcard *.c)
PROGS  = $(patsubst %.c,%,$(SRCS))
CFLAGS = -O0

all: $(PROGS)

%: %.c
	$(CC) $(CFLAGS) -o $@.elf -L./libs -lfoo $<

clean:
	rm -f *.elf
