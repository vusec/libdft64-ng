CC=gcc
CFLAGS=-Og -Wall -Werror
LDFLAGS=-z max-page-size=0x1000
OBJDIR=obj-intel64

PROGRAMS=memtaint
PROGRAMS+=ins

BINARIES=$(addprefix $(OBJDIR)/,$(PROGRAMS))

all: $(BINARIES)

run-all: $(PROGRAMS:=.run)

$(OBJDIR):
	mkdir obj-intel64

%.run: $(OBJDIR)/%
	@echo - Running test $(basename $@)...
	setarch x86_64 -R $(PIN_ROOT)/pin -t ../tools/obj-intel64/track.so -- $<

$(BINARIES): %: $(OBJDIR) %.o
	$(CC) $(LDFLAGS) -o $@ $@.o
	../utils/relink.py $@

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf obj-intel64
