
lib_LTLIBRARIES = src/libbnxtre.la

AM_CFLAGS = -Wall -D_GNU_SOURCE

if HAVE_LD_VERSION_SCRIPT
    bnxtre_version_script = -Wl,--version-script=$(srcdir)/src/bnxtre.map
else
    bnxtre_version_script =
endif

src_libbnxtre_la_SOURCES = src/bnxt_re_main.c src/bnxt_re_verbs.c \
						   src/bnxt_re_memory.c src/bnxt_re_db.c
src_libbnxtre_la_LDFLAGS = -avoid-version -module -release @IBV_DEVICE_LIBRARY_EXTENSION@\
    $(bnxtre_version_script)

bnxtreconfdir = $(sysconfdir)/libibverbs.d
bnxtreconf_DATA = bnxtre.driver

EXTRA_DIST = src/bnxtre.map src/bnxt_re_main.h src/bnxt_re_abi.h	\
			 src/bnxt_re_memory.h src/bnxt_re_verbs.h 				\
			 src/bnxt_re_list.h src/bnxt_re_version.h Changelog		\
			 libbnxtre.spec.in bnxtre.driver README.TXT RELEASE.TXT

dist-hook: libbnxtre.spec
	cp libbnxtre.spec $(distdir)
