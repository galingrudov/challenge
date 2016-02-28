# Makefile for compiling and installing UdpSniffer

#declare some varialbles

TARGETDIR = ./bin
CC=gcc
CFLAGS = -Wall
ODIR = ./obj
objects = $(addprefix $(ODIR)/,UdpSniffer.o)
LDLIBS = -lpcap

all: UdpSniffer 

UdpSniffer: $(objects)
	mkdir -p $(ODIR)
	mkdir -p $(TARGETDIR)
	$(CC) $(CFLAGS) -o $(TARGETDIR)/$@ $^ $(LDLIBS) 

$(objects): src/UdpSniffer.c
	$(CC) -c -o $@ src/UdpSniffer.c

clean :
	rm $(objects)


