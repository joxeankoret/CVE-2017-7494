CFLAGS=-shared -fPIC -Wall -Wno-nonnull
CC=gcc

all: libimplantx64.so libimplantx32.so

libimplantx64.so: implant.c config.h
	$(CC) $(CFLAGS) implant.c -o libimplantx64.so

libimplantx32.so: implant.c config.h
	$(CC) $(CFLAGS) implant.c -o libimplantx32.so -m32

clean:
	rm -f libimplantx*.so
