dnl Process this file with autoconf to produce a configure script.

define(AVFS_MAJOR,[1])
define(AVFS_MINOR,[1])
define(AVFS_PATCH,[4])
define(AVFS_COMMENT,[])

define(AVFS_VERSION,AVFS_MAJOR[.]AVFS_MINOR[.]AVFS_PATCH[]AVFS_COMMENT)
define(AVFS_NUMVERSION,m4_eval(AVFS_MAJOR*100+AVFS_MINOR*10+AVFS_PATCH))

AC_PREREQ([2.50])
AC_INIT([avfs], AVFS_VERSION)
AC_CONFIG_SRCDIR([include/avfs.h])
AM_INIT_AUTOMAKE

AC_CONFIG_HEADER(include/config.h:config.h.in)
AC_PREFIX_DEFAULT(/usr)
AC_CONFIG_MACRO_DIR([macros])

dnl Check if on the same host if reconfiguring

AC_CANONICAL_HOST

AC_MSG_CHECKING([if configuration is valid])
AC_CACHE_VAL(szm_cv_host_system, [szm_cv_host_system=$host])
if test "$host" = "$szm_cv_host_system"; then
  validstring="valid"
else
  validstring="invalid"
fi
AC_MSG_RESULT([$validstring])
if test "$validstring" = invalid; then
  AC_MSG_ERROR([type 'make realclean' before running configure])
fi

VERSION=AVFS_VERSION
AC_SUBST(VERSION)

NUMVERSION=AVFS_NUMVERSION
AC_SUBST(NUMVERSION)

os=`uname -s`
kernver=`uname -r | sed -n 's/\([[0-9]]\+\)\.\([[0-9]]\+\)\..*/\1\2/p'`
if test -z "$kernver"; then
  kernver="0"
fi

AC_MSG_CHECKING([whether to build shared library and/or fuse daemon])

dnl here come the default values
shared=yes
if test "$os" = "Linux"; then
    fuse=yes
fi

AC_ARG_ENABLE([library],
              AC_HELP_STRING([--enable-library],[Compile avfs as a shared or static library]),
              [if test "$enableval" = yes; then shared=yes; else shared=no; fi])

AC_ARG_ENABLE([fuse],
              AC_HELP_STRING([--enable-fuse],[Compile avfsd for fuse]),
              [if test "$enableval" = yes; then fuse=yes; else fuse=no; fi])

shared_build=no
fuse_build=no
build_result=

if test "$shared" = yes; then
   shared_build=yes
   if test -z "$build_result"; then
      build_result=shared
   else
      build_result="$build_result shared"
   fi
fi
if test "$fuse" = yes; then
   fuse_build=yes
   if test -z "$build_result"; then
      build_result=fuse
   else
      build_result="$build_result fuse"
   fi
fi

AC_MSG_RESULT([$build_result])

AC_MSG_CHECKING([whether debugging is enabled])
AC_ARG_ENABLE(debug,
[  --enable-debug          Compile in debug information
  --disable-debug         Do not compile in debug information],
[if test "$enableval" = yes; then debugmode=yes; else debugmode=no; fi],
debugmode=yes)
AC_MSG_RESULT([$debugmode])

AC_MSG_CHECKING([whether building the dav module is enabled])
AC_ARG_ENABLE(dav,
[  --enable-dav            Compile the dav module (requires libneon)],
[if test "$enableval" = yes; then dav=yes; else dav=no; fi],
dav=yes)
AC_MSG_RESULT([$dav])

AC_ARG_WITH(system-zlib,
            AC_HELP_STRING([--with-system-zlib],[Use system zlib instead of builtin]),
            [if test "$withval" = yes; then use_system_zlib=yes; else use_system_zlib=no; fi],
            [use_system_zlib=no])
AM_CONDITIONAL(USE_SYSTEM_ZLIB,[test x$use_system_zlib = xyes])
if test x$use_system_zlib = xyes; then
    AC_DEFINE(USE_SYSTEM_ZLIB, 1, [Define if you want to use system zlib library])
    LIBZ=-lz
    ZLIB_INCLUDE=
else
    LIBZ=../zlib/libzlib.la
    ZLIB_INCLUDE='-I$(top_srcdir)/zlib'
fi
AC_SUBST(LIBZ)
AC_SUBST(ZLIB_INCLUDE)

AC_ARG_WITH(system-bzlib,
            AC_HELP_STRING([--with-system-bzlib],[Use system bzlib instead of builtin]),
            [if test "$withval" = yes; then use_system_bzlib=yes; else use_system_bzlib=no; fi],
            [use_system_bzlib=no])
AM_CONDITIONAL(USE_SYSTEM_BZLIB,[test x$use_system_bzlib = xyes])
if test x$use_system_bzlib = xyes; then
    AC_DEFINE(USE_SYSTEM_BZLIB, 1, [Define if you want to use system bzlib library])
    LIBBZ2=-lbz2
    BZLIB_INCLUDE=
else
    LIBBZ2=../bzlib/libbz.la
    BZLIB_INCLUDE='-I$(top_srcdir)/bzlib'
fi
AC_SUBST(LIBBZ2)
AC_SUBST(BZLIB_INCLUDE)

AC_ARG_WITH(pkgconfigdir,
            AC_HELP_STRING([--with-pkgconfigdir=DIR],[pkgconfig file in DIR @<:@LIBDIR/pkgconfig@:>@]),
            [pkgconfigdir=$withval],
            [pkgconfigdir='${libdir}/pkgconfig'])
AC_SUBST(pkgconfigdir)

dnl Checks for programs.
cflags="$CFLAGS"
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LIBTOOL

PKG_PROG_PKG_CONFIG

AC_SYS_LARGEFILE


fob_set=no
if test "x$ac_cv_sys_file_offset_bits" != x -a "$ac_cv_sys_file_offset_bits" != no; then
  CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=$ac_cv_sys_file_offset_bits"
  fob_set=yes
fi
if test "x$ac_cv_sys_large_files" != x -a "$ac_cv_sys_large_files" != no; then
  CPPFLAGS="$CPPFLAGS -D_LARGE_FILES=$ac_cv_sys_large_files"
fi

if test "$enable_largefile" != no -a "$fob_set" != "yes" -a "$fuse_build" = "yes"; then
  dnl FIXME this is kind of a hack to force the flag _FILE_OFFSET_BITS
  dnl if large file support was requested but the macro decided not to
  dnl use it (for example if arch doesn't need it)
  dnl This is currently required because fuse refuses to work without it
  CPPFLAGS="$CPPFLAGS -D_FILE_OFFSET_BITS=64"
  fob_set=yes
fi

if test -z "$cflags"; then
   if test "$GCC" = yes; then
      if test "$debugmode" = yes; then
         CFLAGS="-Wall -g"
      else 
         CFLAGS="-Wall -O3"
      fi
      ZLIB_CFLAGS="-Wall -O3"
   else
      if test "$debugmode" = yes; then
         CFLAGS="-g"
      else
         CFLAGS="-O"
      fi
      ZLIB_CFLAGS="-O"
   fi
fi

AC_SUBST(ZLIB_CFLAGS)

CPPFLAGS="$CPPFLAGS -D_REENTRANT -D_POSIX_PTHREAD_SEMANTICS -D_GNU_SOURCE"

if test -z "$LD"; then
	AC_CHECK_PROG(LD, ld, [ld -r], [$CC -Wl,-r -nostdlib])
else
	LD="$LD -r"
	AC_SUBST(LD)
fi

AC_CHECK_FUNCS(vsnprintf strncasecmp strcasecmp mkdtemp)
AC_CHECK_FUNCS(getpwuid_r getpwnam_r getgrgid_r getgrnam_r)
AC_CHECK_FUNCS(atoll)
AC_HEADER_MAJOR

dnl For zlib
AC_CHECK_HEADERS(unistd.h)
AC_CHECK_HEADERS(sys/statvfs.h)

AC_CACHE_CHECK([for d_type in struct dirent], my_cv_struct_d_type,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <dirent.h>], [struct dirent d; d.d_type;],
my_cv_struct_d_type=yes, my_cv_struct_d_type=no)])
if test $my_cv_struct_d_type = yes; then
  AC_DEFINE(HAVE_D_TYPE, 1, [Define if your struct direntry has d_type])
fi

AC_CACHE_CHECK([for d_off in struct dirent], my_cv_struct_d_off,
[AC_TRY_COMPILE([#include <sys/types.h>
#include <dirent.h>], [struct dirent d; d.d_off;],
my_cv_struct_d_off=yes, my_cv_struct_d_off=no)])
if test $my_cv_struct_d_off = yes; then
  AC_DEFINE(HAVE_D_OFF, 1, [Define if your struct direntry has d_off])
fi

AC_SEARCH_LIBS(nanosleep, posix4)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(socket, socket inet)

neon_found=no
if test "$dav" = yes; then
  PKG_CHECK_EXISTS([neon],[
                   PKG_CHECK_MODULES([LIBNEON],[neon >= 0.27.0],
                                     [neon_found=yes],[neon_found=no])
                   ])
  if test "$neon_found" = "yes"; then
      AC_DEFINE(HAVE_LIBNEON, 1, [Define to 1 if your system has libneon installed])
      CPPFLAGS="$CPPFLAGS $LIBNEON_CFLAGS"
      LIBS="$LIBS $LIBNEON_LIBS"
      DAV=dav.c
      DAV_LS=dav_ls.c
  else
    DAV=
    DAV_LS=
  fi
else
  DAV=
  DAV_LS=
  LIBDAV=
fi

AM_CONDITIONAL(BUILD_DAVSUPPORT, test x$neon_found = xyes)

AC_SUBST(DAV)
AC_SUBST(DAV_LS)
AC_SUBST(LIBDAV)

AC_CHECK_LIB(dl, dlopen)
AC_CHECK_LIB(pthread, pthread_create)
if test -z "`echo "$LIBS"|grep pthread`"; then
	LIBS="$LIBS -pthread"
fi

moduledir='${libdir}/avfs'

AC_SUBST(moduledir)

install_scriptcomps=

MC_EXTFS_CHECKS

install_fuse=no

dnl ================================================================
dnl == Now comes the stuff for fuse                               ==
dnl ================================================================

run_fuse_test=yes
AC_ARG_ENABLE([fuse-test],
              AC_HELP_STRING([--disable-fuse-test],[Disable test for fuse version]),
              [if test "$enableval" = yes; then run_fuse_test=yes; else run_fuse_test=no; fi])

if test $fuse_build = yes; then
  if test $run_fuse_test = yes; then
    AC_MSG_CHECKING([whether fuse is new enough])

    pkg-config --atleast-version=2.6.0 fuse >/dev/null 2>/dev/null

    if test $? != 0; then
      dnl too old fuse or no fuse or no pkg-config
      dnl in any case disable fuse_build
      AC_MSG_RESULT([no])
      fuse_build=no
    else
      AC_MSG_RESULT([yes])
    fi
  fi
fi

if test $fuse_build = yes; then
    fuse_pkg_found=no
    PKG_CHECK_EXISTS([fuse],[
                     PKG_CHECK_MODULES([LIBFUSE],[fuse],
                                       [fuse_pkg_found=yes])
                     ])

    if test "$fuse_pkg_found" = "yes" -o "$run_fuse_test" = "no"; then
        AC_DEFINE(HAVE_LIBFUSE, 1, [Define to 1 if your system has libfuse installed])
        CPPFLAGS="$CPPFLAGS $LIBFUSE_CFLAGS"
        FUSELIBS="$LIBFUSE_LIBS"
        AC_SUBST(FUSELIBS)
        install_fuse=yes
        install_scriptcomps="$install_scriptcomps mountavfs umountavfs"
    else
        fuse_build=no
    fi

dnl  AC_CHECK_LIB(fuse, fuse_main,[fuse_found=yes],[fuse_found=false])
dnl  if test x$fuse_found == xyes; then
dnl    FUSELIBS="-lfuse"
dnl    AC_SUBST(FUSELIBS)
dnl    install_fuse=yes
dnl    install_scriptcomps="$install_scriptcomps mountavfs umountavfs"
dnl  else
dnl    fuse_build=no
dnl  fi
fi


dnl ================================================================
dnl == check for liblzma                                          ==
dnl ================================================================

have_liblzma=no
use_liblzma=no
AC_ARG_WITH(xz,AC_HELP_STRING([--with-xz],[use xz (default is YES, force to always enable)]),
            ac_cv_use_xz=$withval, ac_cv_use_xz=yes)
if test "$ac_cv_use_xz" = "yes" -o "$ac_cv_use_xz" = "force"; then
    PKG_CHECK_EXISTS([liblzma],[
                     PKG_CHECK_MODULES([LIBLZMA],[liblzma],
                                       [have_liblzma=yes])
                     ])

    dnl AC_MSG_CHECKING(for liblzma)
    if test "$have_liblzma" = "yes" -o "$ac_cv_use_xz" = "force"; then
        AC_DEFINE(HAVE_LIBLZMA, 1, [Define to 1 if your system has liblzma installed])
        CPPFLAGS="$CPPFLAGS $LIBLZMA_CFLAGS"
        LIBS="$LIBS $LIBLZMA_LIBS"
        use_liblzma=yes
    fi
    dnl AC_MSG_RESULT($have_liblzma)
fi

dnl ================================================================
dnl == check for libzstd                                          ==
dnl ================================================================

have_libzstd=no
use_libzstd=no
AC_ARG_WITH(zstd,AC_HELP_STRING([--with-zstd],[use zstd (default is YES)]),
            ac_cv_use_zstd=$withval, ac_cv_use_zstd=yes)
if test "$ac_cv_use_zstd" = "yes"; then
    PKG_CHECK_EXISTS([libzstd],[
                     PKG_CHECK_MODULES([LIBZSTD],[libzstd],
                                       [have_libzstd=yes])
                     ])

    dnl AC_MSG_CHECKING(for libzstd)
    if test "$have_libzstd" = "yes"; then
        AC_DEFINE(HAVE_LIBZSTD, 1, [Define to 1 if your system has libzstd installed])
        CPPFLAGS="$CPPFLAGS $LIBZSTD_CFLAGS"
        LIBS="$LIBS $LIBZSTD_LIBS"
        use_libzstd=yes
    fi
    dnl AC_MSG_RESULT($have_libzstd)
fi

dnl ================================================================
dnl == check for liblzip                                          ==
dnl ================================================================

use_liblzip=no
AC_ARG_WITH(lzip,AC_HELP_STRING([--with-lzip],[use lzip (default is YES)]),
            ac_cv_use_lzip=$withval, ac_cv_use_lzip=yes)
if test "$ac_cv_use_lzip" = "yes"; then
    AC_CHECK_HEADERS(lzlib.h, [AC_CHECK_LIB(lz, LZ_decompress_open,
        [LIBS="$LIBS -llz"
         AC_DEFINE(HAVE_LIBLZIP, 1, [Define to 1 if your system has liblzip installed])
        use_liblzip=yes])])
fi

AM_CONDITIONAL(USE_LIBLZMA, test x$use_liblzma = xyes)
AM_CONDITIONAL(USE_LIBZSTD, test x$use_libzstd = xyes)
AM_CONDITIONAL(USE_LIBLZIP, test x$use_liblzip = xyes)
AM_CONDITIONAL(INSTALL_FUSE, test x$install_fuse = xyes)

dnl ================================================================
dnl == Now comes the stuff that is only for shared                ==
dnl ================================================================

if test $shared_build = yes; then
	install_scriptcomps="$install_scriptcomps avfs-config"
fi
AM_CONDITIONAL(BUILD_SHARED, test x$shared_build = xyes)

dnl Test whether linker supports symbol versioning 

CHECK_LD_VERSIONSCRIPT

AC_SUBST(install_scriptcomps)
AC_SUBST(shared_build)

AC_CONFIG_FILES([pkgconfig/avfs.pc])

AC_OUTPUT([
Makefile
src/Makefile
modules/Makefile
zlib/Makefile
bzlib/Makefile
lib/Makefile
include/Makefile
extfs/Makefile
scripts/Makefile
test/Makefile
spec/Makefile
macros/Makefile
patch/Makefile
doc/Makefile
fuse/Makefile
pkgconfig/Makefile

scripts/avfs-config

extfs/a
extfs/apt
extfs/audio
extfs/deb
extfs/deba
extfs/debd
extfs/dpkg
extfs/hp48
extfs/iso9660
extfs/lslR
extfs/mailfs
extfs/patchfs
extfs/rpms
extfs/u7z
extfs/uace
extfs/uar
extfs/uarj
extfs/uc1541
extfs/uha
extfs/ulha
extfs/upp
extfs/uextrar
extfs/uxdms
extfs/uxpk
extfs/uzip
extfs/uzoo

include/version.h
], [chmod +x scripts/avfs-config])

echo ""
echo "Configuration details:"
if test "$shared_build" = "yes"; then
  echo "  Building library        : yes"
else
  echo "  Building library        : no"
fi
if test "$fuse_build" = "yes"; then
  echo "  Building avfsd for fuse : yes"
else
  echo "  Building avfsd for fuse : no"
fi
echo ""
if test "x$use_system_zlib" = "xyes"; then
  echo "  Use zlib                : system (not recommended, slower random access)"
else
  echo "  Use zlib                : internal (recommended, faster random access)"
fi
if test "x$use_system_bzlib" = "xyes"; then
  echo "  Use bzlib               : system (not recommended, slower random access)"
else
  echo "  Use bzlib               : internal (recommended, faster random access)"
fi
if test "x$use_liblzma" = "xyes"; then
  echo "  Use liblzma             : yes"
else
  echo "  Use liblzma             : no"
fi
if test "x$use_libzstd" = "xyes"; then
  echo "  Use libzstd             : yes"
else
  echo "  Use libzstd             : no"
fi
if test "x$dav" = "xyes" -a "x$neon_found" = "xyes"; then
  echo "  WebDAV support          : yes"
else
  echo "  WebDAV support          : no"
fi
if test "x$use_liblzip" = "xyes"; then
  echo "  Use liblzip             : yes"
else
  echo "  Use liblzip             : no"
fi
echo ""
echo "  Installation prefix     : $prefix"
echo ""
