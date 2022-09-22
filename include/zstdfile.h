/*
    AVFS: A Virtual File System Library
    Copyright (C) 2018  Ralf Hoffmann <ralf@boomerangsworld.de>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    based on bzfile.h
*/


#include "avfs.h"

struct zstdfile;
struct zstdcache;

avssize_t av_zstdfile_pread(struct zstdfile *fil, struct zstdcache *zc, char *buf,
                            avsize_t nbyte, avoff_t offset);

struct zstdfile *av_zstdfile_new(vfile *vf);
int av_zstdfile_size(struct zstdfile *fil, struct zstdcache *zc, avoff_t *sizep);
struct zstdcache *av_zstdcache_new();
