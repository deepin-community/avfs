/*
    AVFS: A Virtual File System Library
    Copyright (C) 2021 Ralf Hoffmann <ralf@boomerangsworld.de>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    based on zstdfile.h
*/

#ifndef LZIPFILE_H
#define LZIPFILE_H

#include "avfs.h"

struct lzipfile;
struct lzipcache;

avssize_t av_lzipfile_pread(struct lzipfile *fil, struct lzipcache *zc, char *buf,
                            avsize_t nbyte, avoff_t offset);

struct lzipfile *av_lzipfile_new(vfile *vf);
int av_lzipfile_size(struct lzipfile *fil, struct lzipcache *zc, avoff_t *sizep);
struct lzipcache *av_lzipcache_new();
avoff_t av_lzipcache_size(struct lzipcache *zc);

#endif /* LZIPFILE_H */
