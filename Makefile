PACKAGE	= umb-freebsd
VERSION	= 1.0.0
SUBDIRS	= kmod sbin/umbctl plugin/umb
INSTALL	= install
LN	= ln -f
MKDIR	= mkdir -p
RM	= rm -f
TAR	= tar

all: kmod plugin umbctl

clean:
	for subdir in $(SUBDIRS); do (cd $$subdir && $(MAKE) clean); done

dist:
	$(LN) -s -- . $(PACKAGE)-$(VERSION)
	$(TAR) czf $(PACKAGE)-$(VERSION).tar.gz \
		$(PACKAGE)-$(VERSION)/Makefile \
		$(PACKAGE)-$(VERSION)/README.md \
		$(PACKAGE)-$(VERSION)/kmod/Makefile \
		$(PACKAGE)-$(VERSION)/kmod/if_umb.c \
		$(PACKAGE)-$(VERSION)/kmod/if_umbreg.h \
		$(PACKAGE)-$(VERSION)/kmod/mbim.h \
		$(PACKAGE)-$(VERSION)/kmod/opt_usb.h \
		$(PACKAGE)-$(VERSION)/plugin/umb/Makefile \
		$(PACKAGE)-$(VERSION)/plugin/umb/+POST_DEINSTALL.post \
		$(PACKAGE)-$(VERSION)/plugin/umb/+POST_INSTALL.post \
		$(PACKAGE)-$(VERSION)/plugin/umb/pkg-descr \
		$(PACKAGE)-$(VERSION)/plugin/umb/src/etc/rc.loader.d/21-umb \
		$(PACKAGE)-$(VERSION)/plugin/umb/src/opnsense/scripts/OPNsense/umb/umbctl-gateway \
		$(PACKAGE)-$(VERSION)/plugin/umb/src/opnsense/service/conf/actions.d/actions_umb.conf \
		$(PACKAGE)-$(VERSION)/sbin/umbctl/Makefile \
		$(PACKAGE)-$(VERSION)/sbin/umbctl/sockio.h \
		$(PACKAGE)-$(VERSION)/sbin/umbctl/umbctl.8 \
		$(PACKAGE)-$(VERSION)/sbin/umbctl/umbctl.c
	$(RM) -- $(PACKAGE)-$(VERSION)
	@echo $(PACKAGE)-$(VERSION).tar.gz

distcheck: dist
	$(TAR) xzf $(PACKAGE)-$(VERSION).tar.gz
	cd $(PACKAGE)-$(VERSION) && $(MAKE)
	$(RM) -r -- $(PACKAGE)-$(VERSION)

distclean: clean

install: all
	for subdir in $(SUBDIRS); do (cd $$subdir && $(MAKE) install); done

kmod:
	cd kmod && $(MAKE)

package: all
	$(MKDIR) plugin/umb/src/boot/modules
	cd kmod && $(MAKE) install \
		DESTDIR=../plugin/umb/src \
		INSTALLFLAGS="-U"
	$(MKDIR) plugin/umb/src/sbin plugin/umb/src/share/man/man8
	cd sbin/umbctl && $(MAKE) install \
		DESTDIR=../../plugin/umb/src \
		TAG_ARGS="-U" \
		MK_DEBUG_FILES=no \
		SHAREDIR=/share
	cd plugin/umb && $(MAKE) package

plugin:
	cd plugin/umb && $(MAKE)

umbctl:
	cd sbin/umbctl && $(MAKE)

.PHONY: all clean dist distcheck distclean install kmod package plugin umbctl
