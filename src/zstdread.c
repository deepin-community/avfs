/*
    AVFS: A Virtual File System Library
    Copyright (C) 2018  Ralf Hoffmann <ralf@boomerangsworld.de>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    based on bzread.c
*/

#include "config.h"
#include "zstdfile.h"
#include "zstd.h"
#include "oper.h"
#include "exit.h"

#include <stdlib.h>
#include <inttypes.h>
#include <fcntl.h>


// we use smaller buffer size than recommened to save memory since we
// may have a lot of objects alive
#define INBUFSIZE 16384
#define OUTBUFSIZE 32768

static int zstdread_nextid;
static AV_LOCK_DECL(zstdread_lock);

struct zstdcache {
    int id;
    avoff_t size;
};

struct zstdfile {
    ZSTD_DStream *s;
    int iseof;
    int iserror;
    int id; /* The id of the last used zstdcache */
    
    vfile *infile;
    char inbuf[INBUFSIZE];

    avoff_t total_in;
    avoff_t total_out;
    ZSTD_inBuffer inBuffer;
    ZSTD_outBuffer outBuffer;
};

static void zstd_delete_stream(ZSTD_DStream *s)
{
    if(s != NULL) {
        size_t res = ZSTD_freeDStream(s);
        if (ZSTD_isError(res)) {
            av_log(AVLOG_ERROR, "ZSTD: error during stream destroy");
        }
    }
}

static int zstd_new_stream(ZSTD_DStream **resp)
{
    int res;
    ZSTD_DStream *s;

    s = ZSTD_createDStream();

    if(s == NULL) {
        *resp = NULL;
        av_log(AVLOG_ERROR, "ZSTD: could not create decompress stream");
        return -EIO;
    }

    res = ZSTD_initDStream(s);
    if (ZSTD_isError(res)) {
        ZSTD_freeDStream(s);
        *resp = NULL;
        av_log(AVLOG_ERROR, "ZSTD: decompress init error: %s", ZSTD_getErrorName(res));
        return -EIO;
    }

    *resp = s;
    return 0;
}

static int zstdfile_reset(struct zstdfile *fil)
{
    zstd_delete_stream(fil->s);

    fil->iseof = 0;
    fil->iserror = 0;
    fil->total_in = fil->total_out = 0;
    memset( &fil->inBuffer, 0, sizeof( fil->inBuffer ) );
    return zstd_new_stream(&fil->s);
}

static int zstdfile_fill_inbuf(struct zstdfile *fil)
{
    avssize_t res;

    if (fil->inBuffer.size > 0 &&
        fil->inBuffer.pos > 0) {
        // there are some remaining bytes from previous calls

        fil->total_in += fil->inBuffer.size;

        if (fil->inBuffer.pos == fil->inBuffer.size) {
            fil->inBuffer.pos = fil->inBuffer.size = 0;
        } else {
            memmove(fil->inbuf,
                    fil->inbuf + fil->inBuffer.pos,
                    fil->inBuffer.size - fil->inBuffer.pos);
            fil->inBuffer.size -= fil->inBuffer.pos;
            fil->inBuffer.pos = 0;
        }
    }

    res = av_pread(fil->infile, fil->inbuf + fil->inBuffer.size, INBUFSIZE - fil->inBuffer.size, fil->total_in);
    if(res < 0)
        return res;
    
    fil->inBuffer.src = fil->inbuf;
    fil->inBuffer.size += res;
    fil->inBuffer.pos = 0;

    return 0;
}

static int zstdfile_decompress(struct zstdfile *fil, struct zstdcache *zc)
{
    int res;

    if (fil->outBuffer.size == 0) return 0;
    
    for (;;) {
        if(fil->inBuffer.pos == fil->inBuffer.size) {
            res = zstdfile_fill_inbuf(fil);
            if(res < 0)
                return res;
            if(fil->inBuffer.size == 0) {
                /* still no byte available */
                av_log(AVLOG_ERROR, "ZSTD: decompress error");
                return -EIO;
            }
        }

        size_t old_out_pos = fil->outBuffer.pos;
        
        size_t r = ZSTD_decompressStream(fil->s,
                                         &fil->outBuffer,
                                         &fil->inBuffer);

        if (ZSTD_isError(r)) {
            av_log(AVLOG_ERROR, "ZSTD: decompress error");
            return -EIO;
        }

        fil->total_out += fil->outBuffer.pos - old_out_pos;

        if (r == 0) {
            //TODO docs are not clear if this really indicates end of file.
            fil->iseof = 1;
            AV_LOCK(zstdread_lock);
            zc->size = fil->total_out;
            AV_UNLOCK(zstdread_lock);
            break;
        }

        if (fil->outBuffer.pos == fil->outBuffer.size) {
            // everything we are requested for is available
            break;
        }
    }

    return 0;
}


static int zstdfile_read(struct zstdfile *fil, struct zstdcache *zc, char *buf,
                         avsize_t nbyte)
{
    int res;
    int sum = 0;

    while (nbyte > 0 && !fil->iseof) {
        fil->outBuffer.dst = buf;
        fil->outBuffer.size = nbyte;
        fil->outBuffer.pos = 0;

        res = zstdfile_decompress(fil, zc);
        if(res < 0)
            return res;

        if (fil->outBuffer.pos == 0) {
            fil->iseof = 1;
        } else {
            buf += fil->outBuffer.pos;
            nbyte -= fil->outBuffer.pos;
            sum += fil->outBuffer.pos;
        }
    }

    return sum;
}

static int zstdfile_skip_to(struct zstdfile *fil, struct zstdcache *zc,
                            avoff_t offset)
{
    int res;
    uint8_t outbuf[OUTBUFSIZE];
    
    while(!fil->iseof) {
        avoff_t curroff = fil->total_out;

        if(curroff == offset)
            break;

        fil->outBuffer.dst = outbuf;
        fil->outBuffer.size = AV_MIN(OUTBUFSIZE, offset - curroff);;
        fil->outBuffer.pos = 0;

        res = zstdfile_decompress(fil, zc);
        if(res < 0)
            return res;

        if (fil->outBuffer.pos == 0) {
            fil->iseof = 1;
        }
    }

    return 0;
}

static avssize_t av_zstdfile_do_pread(struct zstdfile *fil, struct zstdcache *zc,
                                      char *buf, avsize_t nbyte, avoff_t offset)
{
    avssize_t res;
    avoff_t curroff;

    fil->id = zc->id;

    curroff = fil->total_out;
    if(offset != curroff) {
        AV_LOCK(zstdread_lock);
        if ( curroff > offset ) {
            res = zstdfile_reset( fil );
        } else {
            res = 0;
        }
        AV_UNLOCK(zstdread_lock);
        if(res < 0)
            return res;

        res = zstdfile_skip_to(fil, zc, offset);
        if(res < 0)
            return res;
    }

    res = zstdfile_read(fil, zc, buf, nbyte);
    
    return res;
}

avssize_t av_zstdfile_pread(struct zstdfile *fil, struct zstdcache *zc, char *buf,
                            avsize_t nbyte, avoff_t offset)
{
    avssize_t res;

    if(fil->iserror)
        return -EIO;

    res = av_zstdfile_do_pread(fil, zc, buf, nbyte, offset);
    if(res < 0)
        fil->iserror = 1;

    return res;
}

int av_zstdfile_size(struct zstdfile *fil, struct zstdcache *zc, avoff_t *sizep)
{
    int res;
    avoff_t size;

    AV_LOCK(zstdread_lock);
    size = zc->size;
    AV_UNLOCK(zstdread_lock);

    if(size != -1 || fil == NULL) {
        *sizep = size;
        return 0;
    }

    fil->id = zc->id;

    AV_LOCK(zstdread_lock);
    res = zstdfile_reset( fil );
    AV_UNLOCK(zstdread_lock);
    if(res < 0)
        return res;

    res = zstdfile_skip_to(fil, zc, AV_MAXOFF);
    if(res < 0)
        return res;
    
    AV_LOCK(zstdread_lock);
    size = zc->size;
    AV_UNLOCK(zstdread_lock);
    
    if(size == -1) {
        av_log(AVLOG_ERROR, "ZSTD: Internal error: could not find size");
        return -EIO;
    }
    
    *sizep = size;
    return 0;
}

static void zstdfile_destroy(struct zstdfile *fil)
{
    AV_LOCK(zstdread_lock);
    zstd_delete_stream(fil->s);
    AV_UNLOCK(zstdread_lock);
}

struct zstdfile *av_zstdfile_new(vfile *vf)
{
    int res;
    struct zstdfile *fil;

    AV_NEW_OBJ(fil, zstdfile_destroy);
    fil->iseof = 0;
    fil->iserror = 0;
    fil->infile = vf;
    fil->id = 0;
    fil->total_in = fil->total_out = 0;
    memset( &fil->inBuffer, 0, sizeof( fil->inBuffer ) );

    res = zstd_new_stream(&fil->s);
    if(res < 0)
        fil->iserror = 1;

    return fil;
}

static void zstdcache_destroy(struct zstdcache *zc)
{
}

struct zstdcache *av_zstdcache_new()
{
    struct zstdcache *zc;

    AV_NEW_OBJ(zc, zstdcache_destroy);
    zc->size = -1;

    AV_LOCK(zstdread_lock);
    if(zstdread_nextid == 0)
        zstdread_nextid = 1;

    zc->id = zstdread_nextid ++;
    AV_UNLOCK(zstdread_lock);
    
    return zc;
}
