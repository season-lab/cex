SRCS   = $(wildcard *.c)
PROGS  = $(patsubst %.c,%,$(SRCS))
CFLAGS = -O0

all: $(PROGS)

%: %.c
	$(CC) $(CFLAGS) -shared -o lib$@.so $<

clean:
	rm -f *.so
