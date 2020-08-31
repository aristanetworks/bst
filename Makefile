PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share
LIBEXECDIR ?= $(PREFIX)/libexec
MANDIR ?= $(DATADIR)/man

CFLAGS ?= -O2
CFLAGS += -std=c11 -pedantic -Wall -Wextra -Wno-unused-parameter -fno-strict-aliasing
CPPFLAGS ?=
CPPFLAGS += -D_GNU_SOURCE -D_FILE_OFFSET_BITS=64 -DLIBEXECDIR=\"$(LIBEXECDIR)\"

SRCS := \
	capable.c \
	cp.c \
	enter.c \
	kvlist.c \
	bst_limits.c \
	main.c \
	mount.c \
	net.c \
	ns.c \
	outer.c \
	path.c \
	setarch.c \
	sig.c \
	timens.c \
	usage.c \
	userns.c \

OBJS := $(subst .c,.o,$(SRCS))
BINS := bst bst-unpersist bst-init

all: $(BINS) man

TEST_BINS := test/print_limits test/test_limit_parsing

test/test_limit_parsing: bst_limits.o

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

generate: usage.txt
	(echo "/* Copyright © 2020 Arista Networks, Inc. All rights reserved."; \
	 echo " *"; \
	 echo " * Use of this source code is governed by the MIT license that can be found" ;\
	 echo " * in the LICENSE file."; \
	 echo " */"; \
	 echo ""; \
	 echo "/* This file is generated from usage.txt. Do not edit. */"; \
	 xxd -i usage.txt) > usage.c

bst: $(OBJS)
	$(LINK.o) -o $@ $^
	$(SETCAP) cap_setuid,cap_setgid,cap_dac_override,cap_sys_admin,cap_sys_ptrace,cap_sys_chroot,cap_net_admin+p $@ \
		|| ($(CHOWN) root $@ && $(CHMOD) u+s $@)

bst-init: init.o sig.o
	$(LINK.o) -static -o $@ $^

bst-unpersist: unpersist.o capable.o ns.o
	$(LINK.o) -o $@ $^
	$(SETCAP) cap_sys_admin+p $@ \
		|| ($(CHOWN) root $@ && $(CHMOD) u+s $@)

%.gz: %.scd
	scdoc <$< | gzip -c >$@

man: bst.1.gz bst-unpersist.1.gz bst-init.1.gz

install: BST_INSTALLPATH = $(DESTDIR)$(BINDIR)/bst
install: $(BINS) man
	install -m 755 -D bst $(BST_INSTALLPATH)
	install -m 755 -D bst-unpersist $(BST_INSTALLPATH)-unpersist
	install -m 755 -D bst-init $(DESTDIR)$(LIBEXECDIR)/bst-init
	install -m 644 -D bst.1.gz $(DESTDIR)$(MANDIR)/man1/bst.1.gz
	install -m 644 -D bst-unpersist.1.gz $(DESTDIR)$(MANDIR)/man1/bst-unpersist.1.gz
	install -m 644 -D bst-init.1.gz $(DESTDIR)$(MANDIR)/man1/bst-init.1.gz
	$(SETCAP) cap_setuid,cap_setgid,cap_dac_override,cap_sys_admin,cap_sys_ptrace,cap_sys_chroot,cap_net_admin+p $(BST_INSTALLPATH) \
		|| ($(CHOWN) root $(BST_INSTALLPATH) && $(CHMOD) u+s $(BST_INSTALLPATH))
	$(SETCAP) cap_sys_admin+p $(BST_INSTALLPATH)-unpersist \
		|| ($(CHOWN) root $(BST_INSTALLPATH)-unpersist && $(CHMOD) u+s $(BST_INSTALLPATH)-unpersist)

check: export PATH := $(DESTDIR)$(BINDIR):${PATH}
check: $(BINS) $(TEST_BINS)
	./test/cram.sh test
	./test/test_limit_parsing

clean:
	$(RM) $(BINS) $(TEST_BINS) $(OBJS) bst.1.gz

.PHONY: all clean install generate check man
