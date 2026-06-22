noinst_PROGRAMS = runtest testread testreaddir gzip_multimember_test

AM_CFLAGS = -I$(top_srcdir)/include @CFLAGS@ @CPPFLAGS@

runtest_LDFLAGS = @LDFLAGS@ @LIBS@
runtest_LDADD = ../lib/libavfs_static.la
runtest_SOURCES = runtest.c

testread_LDFLAGS = @LDFLAGS@ @LIBS@
testread_LDADD = ../lib/libavfs_static.la
testread_SOURCES = testread.c

testreaddir_LDFLAGS = @LDFLAGS@ @LIBS@
testreaddir_LDADD = ../lib/libavfs_static.la
testreaddir_SOURCES = testreaddir.c

gzip_multimember_test_LDFLAGS = @LDFLAGS@ @LIBS@
gzip_multimember_test_LDADD = ../lib/libavfs_static.la
gzip_multimember_test_SOURCES = gzip_multimember_test.c
