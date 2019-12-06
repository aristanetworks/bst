CFLAGS ?= -O2
CFLAGS += -std=c99 -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing
CPPFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin

SRCS := main.c enter.c userns.c mount.c cp.c setarch.c usage.c
OBJS := $(subst .c,.o,$(SRCS))
BINS := b5-enter b5-enter--userns-helper

ifeq ($(shell id -u),0)
SETUID_BIT = 4
else
SETUID_BIT =
endif

all: $(BINS)

generate: usage.txt
	(echo "/* Copyright (c) 2020 Arista Networks, Inc.  All rights reserved."; \
	 echo "   Arista Networks, Inc. Confidential and Proprietary. */"; \
	 echo ""; \
	 echo "/* This file is generated from usage.txt. Do not edit. */"; \
	 xxd -i usage.txt) > usage.c

b5-enter: $(OBJS)
	$(LINK.o) -o $@ $^

b5-enter--userns-helper: userns-helper.o
	$(LINK.o) -o $@ $^

install: $(BINS)
	install -m 755 -D b5-enter $(DESTDIR)$(BINDIR)/b5-enter
	install -m $(SETUID_BIT)755 -D b5-enter--userns-helper $(DESTDIR)$(BINDIR)/b5-enter--userns-helper

clean:
	$(RM) $(BINS) $(OBJS) userns-helper.o

.PHONY: all clean install generate
