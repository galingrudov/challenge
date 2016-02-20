# Makefile for compiling and installing UdpSniffer

#declare some varialbles

CC=gcc
CP=cp
PROGRAM_NAME=UdpSniffer
exec: UdpSniffer.o
	$(CC) -o bin/$(PROGRAM_NAME) UdpSniffer.o 
UdpSniffer.o: src/UdpSniffer.c
	$(CC) -c src/UdpSniffer.c
