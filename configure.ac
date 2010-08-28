#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.64])
AC_INIT([splitpkcs12], [0.1], [bernat@luffy.cx])
AC_CONFIG_SRCDIR([split.c])
AC_CONFIG_FILES([Makefile])

# Configure automake
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)])

# Checks for programs.
AC_PROG_CC

# OpenSSL
PKG_CHECK_MODULES(OpenSSL, openssl,
		CFLAGS="$CFLAGS `pkg-config --cflags openssl`";
		LIBS="$LIBS `pkg-config --libs openssl`",
		[AC_MSG_FAILURE(OpenSSL is not found.)])

AC_OUTPUT

cat <<EOF

------------------ Summary ------------------
 $PACKAGE_NAME version $PACKAGE_VERSION
  Prefix.........: $prefix
  C Compiler.....: $CC $CFLAGS $CPPFLAGS $LIBS

Compile with:
 ${MAKE-make}

EOF
