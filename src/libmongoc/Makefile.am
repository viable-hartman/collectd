EXTRA_DIST =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =

bin_PROGRAMS =
lib_LTLIBRARIES =
noinst_LTLIBRARIES =
noinst_PROGRAMS =

if WITH_LIBBSON
SUBDIRS = src/libbson
endif

AM_CTAGSFLAGS = --fields=+l --languages=c

<<<<<<< HEAD
<<<<<<< HEAD
# include doc/Makefile.am
# if ENABLE_MAN_PAGES
# include doc/man/Makefile.am
# endif
# if ENABLE_HTML_DOCS
# include doc/html/Makefile.am
# endif
include src/Makefile.am

# if ENABLE_TESTS
# include tests/Makefile.am
# endif

# if ENABLE_EXAMPLES
# include examples/Makefile.am
# endif
=======
include doc/Makefile.am
=======
# include doc/Makefile.am
>>>>>>> Travis build - distcheck missing man pages target, missing header in dist tarball, and clang errors (#135)
# if ENABLE_MAN_PAGES
# include doc/man/Makefile.am
# endif
# if ENABLE_HTML_DOCS
# include doc/html/Makefile.am
# endif
include src/Makefile.am

# if ENABLE_TESTS
# include tests/Makefile.am
# endif

<<<<<<< HEAD
if ENABLE_EXAMPLES
include examples/Makefile.am
endif
>>>>>>> vendoring libmongoc-1.3.5
=======
# if ENABLE_EXAMPLES
# include examples/Makefile.am
# endif
>>>>>>> Disable tests (some of which try to call out to a running server,

# for EXTRA_DIST
include build/cmake/Makefile.am

ACLOCAL_AMFLAGS = -I build/autotools/m4 ${ACLOCAL_FLAGS}
DISTCHECK_CONFIGURE_FLAGS = --enable-silent-rules --enable-man-pages --enable-html-docs --enable-sasl --enable-ssl --enable-maintainer-flags --enable-debug --with-libbson=bundled

mongocdocdir = ${docdir}
mongocdoc_DATA = \
	COPYING \
	NEWS \
	README.rst
EXTRA_DIST += $(mongocdoc_DATA)

EXTRA_DIST += \
	CMakeLists.txt \
	CONTRIBUTING.md \
	VERSION_CURRENT \
	VERSION_RELEASED

EXTRA_DIST += $(wildcard orchestration_configs/*/*)

dist-hook:
	@if test -d "$(srcdir)/.git"; then                              \
          (cd "$(srcdir)" &&                                            \
           $(top_srcdir)/build/autotools/missing --run git log --stat ) > ChangeLog.tmp \
           && mv -f ChangeLog.tmp $(top_distdir)/ChangeLog              \
           || (rm -f ChangeLog.tmp;                                     \
               echo Failed to generate ChangeLog >&2);                  \
	else                                                            \
	  echo A git checkout is required to generate a ChangeLog >&2;  \
	fi

uninstall-local:
	-rm -r $(mongocdocdir)

dist-rpm: dist-gzip
	cp mongo-c-driver-$(MONGOC_VERSION).tar.gz ~/rpmbuild/SOURCES/
	rpmbuild -bb build/rpm/mongo-c-driver.spec
