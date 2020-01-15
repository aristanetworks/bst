PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
LIBEXECDIR ?= $(PREFIX)/libexec

CFLAGS ?= -O2
CFLAGS += -std=c99 -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing
CPPFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DLIBEXECDIR=\"$(LIBEXECDIR)\"

SRCS := main.c enter.c userns.c mount.c cp.c setarch.c usage.c signal.c
OBJS := $(subst .c,.o,$(SRCS))
BINS := bst bst--userns-helper

ifeq ($(shell id -u),0)
SUDO =
else
SUDO = sudo
endif

ifeq ($(NO_SETCAP),)
SETCAP = $(SUDO) setcap
else
SETCAP = :
endif

all: $(BINS)

generate: usage.txt
	(echo "/* Copyright (c) 2020 Arista Networks, Inc.  All rights reserved."; \
	 echo "   Arista Networks, Inc. Confidential and Proprietary. */"; \
	 echo ""; \
	 echo "/* This file is generated from usage.txt. Do not edit. */"; \
	 xxd -i usage.txt) > usage.c

bst: $(OBJS)
	$(LINK.o) -o $@ $^ -lcap

bst--userns-helper: userns-helper.o
	$(LINK.o) -o $@ $^
	$(SETCAP) cap_setuid,cap_setgid+ep $@

install: $(BINS)
	install -m 755 -D bst $(DESTDIR)$(BINDIR)/bst
	install -m 755 -D bst--userns-helper $(DESTDIR)$(LIBEXECDIR)/bst--userns-helper
	$(SETCAP) cap_setuid,cap_setgid+ep $(DESTDIR)$(LIBEXECDIR)/bst--userns-helper

clean:
	$(RM) $(BINS) $(OBJS) userns-helper.o

.PHONY: all clean install generate
