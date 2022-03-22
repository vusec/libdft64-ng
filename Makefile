# Dependencies:
# sudo apt-get install gcc-multilib g++-multilib

CC=clang
CXX=clang++

LIBDFT_SRC			= src
LIBDFT_TOOL			= tools
LIBDFT_TEST			= tests
# LIBDFT_TAG_FLAGS	?= -DLIBDFT_TAG_TYPE=libdft_tag_uint8


.PHONY: all
all: dftsrc tool test

test: $(LIBDFT_TEST)
	cd $< && CPPFLAGS="$(CPPFLAGS)" $(MAKE)

.PHONY: dftsrc mytool
dftsrc: $(LIBDFT_SRC)
	cd $< && CPPFLAGS="$(CPPFLAGS)" DFTFLAGS=$(LIBDFT_TAG_FLAGS) $(MAKE)

tool: $(LIBDFT_TOOL) dftsrc
	# cd $< && TARGET=ia32 CPPFLAGS="$(CPPFLAGS)" DFTFLAGS=$(LIBDFT_TAG_FLAGS) $(MAKE)
	cd $< && TARGET=intel64 CPPFLAGS="$(CPPFLAGS)" DFTFLAGS=$(LIBDFT_TAG_FLAGS) $(MAKE)

.PHONY: clean
clean:
	cd $(LIBDFT_SRC) && $(MAKE) clean
	cd $(LIBDFT_TOOL) && $(MAKE) clean
	cd $(LIBDFT_TEST) && $(MAKE) clean
