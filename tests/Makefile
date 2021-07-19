CC=gcc
CFLAGS=-Og -Wall -Werror
OBJDIR=obj-intel64

PROGRAMS=memtaint

BINARIES=$(addprefix $(OBJDIR)/,$(PROGRAMS))

BIN_PREP_memtaint=../utils/relink.py $(OBJDIR)/memtaint
PIN_EXEC_memtaint=setarch -R

all: $(BINARIES)

run-all: $(PROGRAMS:=.run)

$(OBJDIR):
	mkdir obj-intel64

%.run: $(OBJDIR)/%
	@echo - Running test $(basename $@)...
	$(PIN_EXEC_$(basename $@)) $(PIN_ROOT)/pin -t ../tools/obj-intel64/track.so -- $<

$(BINARIES): %: $(OBJDIR) %.o
	$(CC) $(LDFLAGS) -o $@ $@.o
	$(BIN_PREP_$(@F))

$(OBJDIR)/%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf obj-intel64
