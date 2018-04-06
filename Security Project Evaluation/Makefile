CC  = gcc
CXX = g++

CFLAGS   = -g -Wall $(INCLUDES)
CXXFLAGS = -g -Wall $(INCLUDES)

LDLIBS=-lcrypto

.PHONY: default
default: server_handler client
	rm -f *.o *~

server_handler: ids.o ftp.o ErrorOut.o

server_handler.o: server_handler.c

ids.o: ids.c

ftp.o: ftp.c

ErrorOut.o: ErrorOut.c

client: client.c

.PHONY: clean
clean:
	rm -f *.o *~ a.out core server_handler client

.PHONY: all
all: clean default
