ACLOCAL_AMFLAGS = -I libltdl/m4

if BUILD_WITH_OWN_LIBMONGOC
LIBMONGOC_SUBDIR=src/libmongoc
endif

SUBDIRS = $(LIBMONGOC_SUBDIR) proto src bindings .

if BUILD_INCLUDED_LTDL
SUBDIRS += libltdl
endif

AM_CPPFLAGS = $(LTDLINCL)

EXTRA_DIST = contrib version-gen.sh testwrapper.sh

install-exec-hook:
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/run
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/lib/$(PACKAGE_NAME)
	$(mkinstalldirs) $(DESTDIR)$(localstatedir)/log

maintainer-clean-local:
	-rm -f -r libltdl
	-rm -f INSTALL
	-rm -f aclocal.m4
