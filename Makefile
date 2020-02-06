PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
MANDIR ?= $(DATADIR)/man

CFLAGS ?= -O2
CFLAGS += -std=c99 -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing
CPPFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 $(HAVE_FLAGS)
ifneq ($(shell $(CC) features/clone_newcgroup_test.c || echo notfound),notfound)
HAVE_FLAGS += -DHAVE_CLONE_NEWCGROUP=1
endif

SRCS := main.c enter.c userns.c mount.c cp.c setarch.c usage.c sig.c
OBJS := $(subst .c,.o,$(SRCS))
BINS := bst

ifeq ($(shell id -u),0)
SUDO =
else
SUDO = sudo
endif

ifeq ($(NO_SETCAP_OR_SUID),)
SETCAP ?= $(SUDO) setcap
CHOWN = $(SUDO) chown
CHMOD = $(SUDO) chmod
else
SETCAP = :
CHOWN = :
CHMOD = :
endif

all: $(BINS) man

generate: usage.txt
	(echo "/* Copyright (c) 2020 Arista Networks, Inc.  All rights reserved."; \
	 echo "   Arista Networks, Inc. Confidential and Proprietary. */"; \
	 echo ""; \
	 echo "/* This file is generated from usage.txt. Do not edit. */"; \
	 xxd -i usage.txt) > usage.c

bst: $(OBJS)
	$(LINK.o) -o $@ $^ -lcap
	$(SETCAP) cap_setuid,cap_setgid,cap_dac_override,cap_sys_admin+ep $@ \
		|| ($(CHOWN) root $@ && $(CHMOD) u+s $@)

%.gz: %.scd
	scdoc <$< | gzip -c >$@

man: bst.1.gz

install: BST_INSTALLPATH = $(DESTDIR)$(BINDIR)/bst
install: $(BINS) man
	install -m 755 -D bst $(BST_INSTALLPATH)
	$(SETCAP) cap_setuid,cap_setgid,cap_dac_override,cap_sys_admin+ep $(BST_INSTALLPATH) \
		|| ($(CHOWN) root $(BST_INSTALLPATH) && $(CHMOD) u+s $(BST_INSTALLPATH))
	install -m 644 -D bst.1.gz $(DESTDIR)$(MANDIR)/man1/bst.1.gz

check: export PATH := $(DESTDIR)$(BINDIR):${PATH}
check: $(BINS)
	./test/cram.sh test

clean:
	$(RM) $(BINS) $(OBJS)

.PHONY: all clean install generate check man
