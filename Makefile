PKGNAME		= pcr-oracle-0.3

CCOPT		= -O0 -g
FIRSTBOOTDIR	= /usr/share/jeos-firstboot
CFLAGS		= -Wall -I /usr/include/tss2 $(CCOPT)
TSS2_LINK	= -ltss2-esys -ltss2-tctildr -ltss2-rc -ltss2-mu -lcrypto
TOOLS		= pcr-oracle

ORACLE_SRCS	= oracle.c \
		  pcr.c \
		  rsa.c \
		  pcr-policy.c \
		  eventlog.c \
		  efi-devpath.c \
		  efi-variable.c \
		  efi-application.c \
		  efi-gpt.c \
		  shim.c \
		  digest.c \
		  runtime.c \
		  authenticode.c \
		  ima.c \
		  platform.c \
		  testcase.c \
		  bufparser.c \
		  util.c
ORACLE_OBJS	= $(addprefix build/,$(patsubst %.c,%.o,$(ORACLE_SRCS)))

all: $(TOOLS)

install:: $(TOOLS)
	install -d $(DESTDIR)/bin
	install -m 755 $(TOOLS) $(DESTDIR)/bin

clean:
	rm -f $(TOOLS)
	rm -rf build

pcr-oracle: $(ORACLE_OBJS)
	$(CC) -o $@ $(ORACLE_OBJS) $(TSS2_LINK)

build/%.o: src/%.c
	@mkdir -p build
	$(CC) -o $@ $(CFLAGS) -c $<

dist:
	mkdir -p $(PKGNAME)
	cp -a Makefile README.md src $(PKGNAME)
	tar cvjf $(PKGNAME).tar.bz2 $(PKGNAME)/*
	rm -rf $(PKGNAME)
