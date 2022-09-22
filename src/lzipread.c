/*
    AVFS: A Virtual File System Library
    Copyright (C) 2021 Ralf Hoffmann <ralf@boomerangsworld.de>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    based on zstdread.c
*/

#include "config.h"
#include "lzipfile.h"
#include "oper.h"
#include "exit.h"

#include <stdlib.h>
#include <inttypes.h>
#include <fcntl.h>
#include <lzlib.h>

#define INDEXDISTANCE 1048576
#define LOOKUP_COST_DISTANCE (16 * 1024) // cost for searching for
                                         // cached member post instead
                                         // of just seeking forward

#define INBUFSIZE 16384
#define OUTBUFSIZE 32768

static AV_LOCK_DECL(lzipread_lock);

struct lzipindex {
    avoff_t o_offset;          /* The number of output bytes */
    avoff_t i_offset;        /* The offset within the input file where the member begins */
    struct lzipindex *next;
};

struct lzipcache {
    avoff_t cachesize;  // size of cache used to decide for cleanup
    avoff_t nextindex;  // min position when next index should happen
    avoff_t size;       // output file size
    struct lzipindex *indexes;
};

struct lzipfile {
    struct LZ_Decoder *decoder;
    int iseof;
    int iserror;
    
    vfile *infile;

    avoff_t total_in;
    avoff_t total_out;
    avoff_t last_member_pos;

    char *outbuf;
    size_t outbuf_size;
    size_t output_pos;
};

static void lzip_delete_decoder(struct LZ_Decoder *decoder)
{
    if(decoder != NULL) {
        LZ_decompress_close(decoder);
    }
}

static int lzip_new_decoder(struct LZ_Decoder **resp)
{
    struct LZ_Decoder *decoder;

    decoder = LZ_decompress_open();

    if(decoder == NULL) {
        *resp = NULL;
        av_log(AVLOG_ERROR, "LZIP: could not create decompress decoder");
        return -EIO;
    }

    *resp = decoder;
    return 0;
}

static int lzipfile_reset(struct lzipfile *fil)
{
    lzip_delete_decoder(fil->decoder);

    fil->iseof = 0;
    fil->iserror = 0;
    fil->total_in = fil->total_out = 0;
    fil->last_member_pos = 0;
    return lzip_new_decoder(&fil->decoder);
}

static int lzipfile_save_index(struct lzipfile *fil, struct lzipcache *zc,
                               avoff_t o_offset,
                               avoff_t i_offset)
{
    struct lzipindex **zp;
    struct lzipindex *zi;

    for(zp = &zc->indexes; *zp != NULL; zp = &(*zp)->next);

    AV_NEW(zi);
    zi->o_offset = o_offset;
    zi->i_offset = i_offset;
    zi->next = NULL;
    
    *zp = zi;

    zc->nextindex += INDEXDISTANCE;
    zc->cachesize += sizeof(*zi);
    
    return 0;
}

static struct lzipindex *lzipcache_find_index(struct lzipcache *c, avoff_t offset)
{
    struct lzipindex *prevzi;
    struct lzipindex *zi;
    
    prevzi = NULL;
    for(zi = c->indexes; zi != NULL; zi = zi->next) {
        if(zi->o_offset > offset)
            break;
        prevzi = zi;
    }

    return prevzi;
}

static int lzipfile_fill_inbuf(struct lzipfile *fil)
{
    avssize_t res;
    char buf[INBUFSIZE];
    int ret;
    int size = AV_MIN(sizeof(buf), LZ_decompress_write_size(fil->decoder));

    if (size <= 0) {
        return 0;
    }
    
    res = av_pread(fil->infile, buf, size, fil->total_in);
    if(res < 0)
        return res;

    ret = LZ_decompress_write(fil->decoder, (const uint8_t*)buf, res);
    if ( ret < 0 ) {
        return ret;
    }

    fil->total_in += ret;

    if ( res == 0 ) {
        LZ_decompress_finish(fil->decoder);
    }
    
    return 0;
}

static int lzipfile_decompress(struct lzipfile *fil, struct lzipcache *zc)
{
    int res;
    int ret;

    if (fil->outbuf_size == 0) return 0;
    
    for (;;) {
        res = lzipfile_fill_inbuf(fil);
        if(res < 0)
            return res;

        ret = LZ_decompress_read(fil->decoder, (uint8_t*)fil->outbuf + fil->output_pos, fil->outbuf_size - fil->output_pos);
        if( ret < 0 ) {
            av_log(AVLOG_ERROR, "LZIP: decompress error");
            return -EIO;
        }
        if (LZ_decompress_member_finished(fil->decoder)){
            AV_LOCK(lzipread_lock);
            if(fil->total_out + ret >= zc->nextindex) {
                res = lzipfile_save_index(fil, zc,
                                          fil->total_out + ret,
                                          fil->last_member_pos + LZ_decompress_member_position(fil->decoder));
            }
            AV_UNLOCK(lzipread_lock);

            fil->last_member_pos += LZ_decompress_member_position(fil->decoder);
        }

        fil->total_out += ret;
        fil->output_pos += ret;

        if (ret == 0) {
            if (LZ_decompress_total_in_size(fil->decoder) == fil->total_in) {
                fil->iseof = 1;
                AV_LOCK(lzipread_lock);
                zc->size = fil->total_out;
                AV_UNLOCK(lzipread_lock);
                break;
            }
        }

        if (fil->output_pos == fil->outbuf_size) {
            // everything we are requested for is available
            break;
        }
    }

    return 0;
}


static int lzipfile_read(struct lzipfile *fil, struct lzipcache *zc, char *buf,
                         avsize_t nbyte)
{
    int res;
    int sum = 0;

    while (nbyte > 0 && !fil->iseof) {
        fil->outbuf = buf;
        fil->outbuf_size = nbyte;
        fil->output_pos = 0;

        res = lzipfile_decompress(fil, zc);
        if(res < 0)
            return res;

        if (fil->output_pos == 0) {
            fil->iseof = 1;
        } else {
            buf += fil->output_pos;
            nbyte -= fil->output_pos;
            sum += fil->output_pos;
        }
    }

    return sum;
}

static int lzipfile_skip_to(struct lzipfile *fil, struct lzipcache *zc,
                            avoff_t offset)
{
    int res;
    char outbuf[OUTBUFSIZE];
    
    while(!fil->iseof) {
        avoff_t curroff = fil->total_out;

        if(curroff == offset)
            break;

        fil->outbuf = outbuf;
        fil->outbuf_size = AV_MIN(OUTBUFSIZE, offset - curroff);;
        fil->output_pos = 0;

        res = lzipfile_decompress(fil, zc);
        if(res < 0)
            return res;

        if (fil->output_pos == 0) {
            fil->iseof = 1;
        }
    }

    return 0;
}

static int lzipfile_seek(struct lzipfile *fil, struct lzipcache *zc, avoff_t offset)
{
    struct lzipindex *zi;

    if ( fil->total_out < offset && offset - fil->total_out < LOOKUP_COST_DISTANCE ) {
        // do nothing if we just need to go slightly forward
        return 0;
    }
    
    zi = lzipcache_find_index(zc, offset);

    if(zi == NULL) {
        if (fil->total_out > offset) {
            return lzipfile_reset(fil);
        }
    } else {
        int res;

        if ( zi->o_offset < fil->total_out &&
             offset > fil->total_out ) {
            return 0;
        }

        res = lzipfile_reset(fil);
        if ( res < 0 ) {
            return res;
        }
        fil->total_in = zi->i_offset;
        fil->total_out = zi->o_offset;
        fil->last_member_pos = zi->i_offset;

        LZ_decompress_sync_to_member(fil->decoder);
    }
    
    return 0;
}

static int lzipfile_goto(struct lzipfile *fil, struct lzipcache *zc, avoff_t offset)
{
    int res;

    AV_LOCK(lzipread_lock);
    res = lzipfile_seek(fil, zc, offset);
    AV_UNLOCK(lzipread_lock);
    if(res == 0) {
        res = lzipfile_skip_to(fil, zc, offset);
    }

    return res;
}

static avssize_t av_lzipfile_do_pread(struct lzipfile *fil, struct lzipcache *zc,
                                      char *buf, avsize_t nbyte, avoff_t offset)
{
    avssize_t res;
    avoff_t curroff;

    curroff = fil->total_out;
    if(offset != curroff) {
        res = lzipfile_goto(fil, zc, offset);
        if(res < 0)
            return res;
    }

    res = lzipfile_read(fil, zc, buf, nbyte);
    
    return res;
}

avssize_t av_lzipfile_pread(struct lzipfile *fil, struct lzipcache *zc, char *buf,
                            avsize_t nbyte, avoff_t offset)
{
    avssize_t res;

    if(fil->iserror)
        return -EIO;

    res = av_lzipfile_do_pread(fil, zc, buf, nbyte, offset);
    if(res < 0)
        fil->iserror = 1;

    return res;
}

int av_lzipfile_size(struct lzipfile *fil, struct lzipcache *zc, avoff_t *sizep)
{
    int res;
    avoff_t size;

    AV_LOCK(lzipread_lock);
    size = zc->size;
    AV_UNLOCK(lzipread_lock);

    if(size != -1 || fil == NULL) {
        *sizep = size;
        return 0;
    }

    res = lzipfile_reset( fil );
    if(res < 0)
        return res;

    res = lzipfile_skip_to(fil, zc, AV_MAXOFF);
    if(res < 0)
        return res;
    
    AV_LOCK(lzipread_lock);
    size = zc->size;
    AV_UNLOCK(lzipread_lock);
    
    if(size == -1) {
        av_log(AVLOG_ERROR, "LZIP: Internal error: could not find size");
        return -EIO;
    }
    
    *sizep = size;
    return 0;
}

static void lzipfile_destroy(struct lzipfile *fil)
{
    lzip_delete_decoder(fil->decoder);
}

struct lzipfile *av_lzipfile_new(vfile *vf)
{
    int res;
    struct lzipfile *fil;

    AV_NEW_OBJ(fil, lzipfile_destroy);
    fil->iseof = 0;
    fil->iserror = 0;
    fil->infile = vf;
    fil->total_in = fil->total_out = 0;
    fil->last_member_pos = 0;

    res = lzip_new_decoder(&fil->decoder);
    if(res < 0)
        fil->iserror = 1;

    return fil;
}

static void lzipcache_destroy(struct lzipcache *zc)
{
    struct lzipindex *zi;
    struct lzipindex *nextzi;

    for(zi = zc->indexes; zi != NULL; zi = nextzi) {
        nextzi = zi->next;
        av_free(zi);
    }
}

struct lzipcache *av_lzipcache_new()
{
    struct lzipcache *zc;

    AV_NEW_OBJ(zc, lzipcache_destroy);
    zc->size = -1;
    zc->cachesize = 0;
    zc->indexes = NULL;
    zc->nextindex = INDEXDISTANCE;

    return zc;
}

avoff_t av_lzipcache_size(struct lzipcache *zc)
{
    return zc->cachesize;
}
