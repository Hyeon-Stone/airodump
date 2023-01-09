LDLIBS= -lpcap -lcurses

all: airodump

print.o: print.h print.cpp hdr.h

parse.o: parse.h parse.cpp hdr.h


airodump: main.o print.o parse.o hdr.h
	$(LINK.cc) -w $^ $(LOADLIBES) $(LDLIBS) -o $@
	rm -f *.o
clean:
	rm -f arp-spoof *.o

