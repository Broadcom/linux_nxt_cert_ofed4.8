#!/usr/bin/make

KVER=
ifeq ($(KVER),)
    KVER=$(shell uname -r)
endif

PREFIX=

default: build


l2build:
	make -C bnxt_en KVER=$(KVER) PREFIX=$(PREFIX)

l2install:
	make -C bnxt_en KVER=$(KVER) PREFIX=$(PREFIX) install

l2clean:
	make -C bnxt_en clean

rocebuild:
	make -C bnxt_re KVER=$(KVER) PREFIX=$(PREFIX)

roceinstall:
	make -C bnxt_re KVER=$(KVER) PREFIX=$(PREFIX) install

roceclean:
	make -C bnxt_re clean

build: l2build rocebuild

install: build l2install roceinstall

clean: l2clean roceclean

.PHONEY: all clean install
                                         
