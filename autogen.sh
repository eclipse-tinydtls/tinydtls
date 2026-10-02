#! /bin/sh -e

srcdir=`dirname "$0"`

GENERATED_FILES="aclocal.m4 ar-lib compile depcomp src/.dirstamp
               Makefile aes/Makefile doc/Makefile ecc/Makefile
               platform-specific/Makefile sha2/Makefile
               tests/Makefile tests/unit-tests/Makefile
               config.status configure config.log tinydtls.pc
               m4/libtool.m4 m4/lt~obsolete.m4 m4/ltoptions.m4 m4/ltsugar.m4 m4/ltversion.m4"

GENERATED_DIRS="autom4te.cache src/.deps"

if test "x$1" = "x--clean"; then
    rm -f $GENERATED_FILES
    rm -rf $GENERATED_DIRS
    exit 0
fi

# create fake ar-lib if not present
test -e ar-lib || touch ar-lib
autoreconf --force --install --verbose "$srcdir"
