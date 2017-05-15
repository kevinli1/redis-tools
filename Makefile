CC = gcc
CFLAGS = -g -Wall
CINCLUDES = -I./deps/libpcap/ -I./deps/lua/src
CLIBS = ./deps/libpcap/libpcap.a ./deps/lua/src/liblua.a
LOAD_LIBS=-lm -ldl

INSTALL=/usr/bin/install
INSTALLDIR=/usr/local
BINDIR=$(INSTALLDIR)/bin

REDIS-TOOLS_CC = $(CC) $(CFLAGS) $(CINCLUDES)

PROG = redis-tools


OBJS = utils.o cJSON.o pcap_packet.o script.o redis-tools.o

all: deps redis-tools
.PHONY: all

include dep.mk
redis-tools: $(OBJS) 
	$(CC) $(CFLAGS) -o $(PROG) $(OBJS) $(CINCLUDES) $(CLIBS) $(LOAD_LIBS)

%.o: %.c
	$(REDIS-TOOLS_CC) -c $<

dep:
	$(REDIS-TOOLS_CC) -MM *.c > dep.mk

uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
ifeq ($(uname_S),SunOS)
	os_Platform := solaris 
else
ifeq ($(uname_S),Darwin)
	os_Platform := macosx
else
ifeq ($(uname_S),AIX)
	os_Platform := aix
else
	os_Platform := linux
endif
endif
endif

deps: nop 
	@cd ./deps/libpcap/  && ./configure && make
	@cd ./deps/lua/src && make $(os_Platform)

clean:
	- rm -rf $(PROG) && rm -rf  *.o 
	@cd ./deps/libpcap/ && make clean
	@cd ./deps/lua/src/ && make clean
nop:

install:
	mkdir -p $(BINDIR)
	$(INSTALL) $(PROG) $(BINDIR)
