# Makefile for compiling and installing UdpSniffer

#declare some varialbles

TARGETDIR = ./bin
CC=gcc
CFLAGS = -Wall
ODIR = ./obj
objects = $(addprefix $(ODIR)/,UdpSniffer.o)
LDLIBS = -lpcap -lrt
#librt (-lrt) 
all: UdpSniffer 

$(ODIR):
	mkdir -p $(ODIR)

UdpSniffer: $(ODIR) $(objects)
	mkdir -p $(TARGETDIR)
	$(CC) $(CFLAGS) -o $(TARGETDIR)/$@ $(objects) $(LDLIBS) 

$(objects): src/UdpSniffer.c
	$(CC) -c -o $@ src/UdpSniffer.c

clean :
	rm $(objects)


