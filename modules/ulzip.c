/*  
    AVFS: A Virtual File System Library
    Copyright (C) 2021 Ralf Hoffmann <ralf@boomerangsworld.de>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    ULZIP module (based on UZSTD module)
*/

#include "version.h"

#include "lzipfile.h"
#include "filecache.h"
#include "cache.h"
#include "oper.h"
#include "version.h"

struct lzipnode {
    avmutex lock;
    struct avstat sig;
    struct cacheobj *cache;
    avino_t ino;
};

struct lziphandle {
    struct lzipfile *zfil;
    vfile *base;
    struct lzipnode *node;
};


static void lzipnode_destroy(struct lzipnode *nod)
{
    av_unref_obj(nod->cache);
    AV_FREELOCK(nod->lock);
}

static struct lzipnode *lzip_new_node(ventry *ve, struct avstat *stbuf)
{
    struct lzipnode *nod;

    AV_NEW_OBJ(nod, lzipnode_destroy);
    AV_INITLOCK(nod->lock);
    nod->sig = *stbuf;
    nod->cache = NULL;
    nod->ino = av_new_ino(ve->mnt->avfs);
    
    return nod;
}

static int lzip_same(struct lzipnode *nod, struct avstat *stbuf)
{
    if(nod->sig.ino == stbuf->ino &&
       nod->sig.dev == stbuf->dev &&
       nod->sig.size == stbuf->size &&
       AV_TIME_EQ(nod->sig.mtime, stbuf->mtime))
        return 1;
    else
        return 0;
}

static struct lzipnode *lzip_do_get_node(ventry *ve, const char *key,
                                         struct avstat *stbuf)
{
    static AV_LOCK_DECL(lock);
    struct lzipnode *nod;

    AV_LOCK(lock);
    nod = (struct lzipnode *) av_filecache_get(key);
    if(nod != NULL) {
        if(!lzip_same(nod, stbuf)) {
            av_unref_obj(nod);
            nod = NULL;
        }
    }
    
    if(nod == NULL) {
        nod =  lzip_new_node(ve, stbuf);
        av_filecache_set(key, nod);
    }
    AV_UNLOCK(lock);

    return nod;
}

static int lzip_getnode(ventry *ve, vfile *base, struct lzipnode **resp)
{
    int res;
    struct avstat stbuf;
    const int attrmask = AVA_INO | AVA_DEV | AVA_SIZE | AVA_MTIME;
    struct lzipnode *nod;
    char *key;

    res = av_fgetattr(base, &stbuf, attrmask);
    if(res < 0)
        return res;

    res = av_filecache_getkey(ve, &key);
    if(res < 0)
        return res;

    nod = lzip_do_get_node(ve, key, &stbuf);

    av_free(key);

    *resp = nod;
    return 0;
}

static struct lzipcache *lzip_getcache(ventry *base, struct lzipnode *nod)
{
    struct lzipcache *cache;
    
    cache = (struct lzipcache *) av_cacheobj_get(nod->cache);
    if(cache == NULL) {
        int res;
        char *name;

        res = av_generate_path(base, &name);
        if(res < 0)
            name = NULL;
        else
            name = av_stradd(name, "(index)", NULL);

        cache = av_lzipcache_new();
        av_unref_obj(nod->cache);

        /* FIXME: the cacheobj should only be created when the lzipcache
           is nonempty */
        nod->cache = av_cacheobj_new(cache, name);
        av_free(name); 
    }

    return cache;
}

static int lzip_lookup(ventry *ve, const char *name, void **newp)
{
    char *path = (char *) ve->data;
    
    if(path == NULL) {
        if(name[0] != '\0')
            return -ENOENT;
	if(ve->mnt->opts[0] != '\0')
            return -ENOENT;
        path = av_strdup(name);
    }
    else if(name == NULL) {
        av_free(path);
        path = NULL;
    }
    else 
        return -ENOENT;
    
    *newp = path;
    return 0;
}

static int lzip_access(ventry *ve, int amode)
{
    return av_access(ve->mnt->base, amode);
}

static int lzip_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    int res;
    vfile *base;
    struct lzipnode *nod;
    struct lziphandle *fil;

    if(flags & AVO_DIRECTORY)
        return -ENOTDIR;

    if(AV_ISWRITE(flags))
        return -EROFS;

    res = av_open(ve->mnt->base, AVO_RDONLY, 0, &base);
    if(res < 0)
        return res;

    res = lzip_getnode(ve, base, &nod);
    if(res < 0) {
        av_close(base);
        return res;
    }

    AV_NEW(fil);
    if((flags & AVO_ACCMODE) != AVO_NOPERM)
        fil->zfil = av_lzipfile_new(base);
    else
        fil->zfil = NULL;

    fil->base = base;
    fil->node = nod;
    
    *resp = fil;
    return 0;
}

static int lzip_close(vfile *vf)
{
    struct lziphandle *fil = (struct lziphandle *) vf->data;

    av_unref_obj(fil->zfil);
    av_unref_obj(fil->node);
    av_close(fil->base);
    av_free(fil);

    return 0;
}

static avssize_t lzip_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct lziphandle *fil = (struct lziphandle *) vf->data;
    struct lzipcache *zc;
    struct cacheobj *cobj;
    avoff_t prev_cachesize;

    AV_LOCK(fil->node->lock);
    zc = lzip_getcache(vf->mnt->base, fil->node);
    cobj = fil->node->cache;
    av_ref_obj(cobj);
    AV_UNLOCK(fil->node->lock);

    prev_cachesize = av_lzipcache_size(zc);
    
    res = av_lzipfile_pread(fil->zfil, zc, buf, nbyte, vf->ptr);
    if(res > 0) {
        avoff_t new_cachesize;

        vf->ptr += res;

        new_cachesize = av_lzipcache_size(zc);
        if (new_cachesize != prev_cachesize) {
            av_cacheobj_setsize(cobj, new_cachesize);
        }
    } else {
        AV_LOCK(fil->node->lock);
        av_unref_obj(fil->node->cache);
        fil->node->cache = NULL;
        AV_UNLOCK(fil->node->lock);
    }

    av_unref_obj(zc);
    av_unref_obj(cobj);

    return res;
}

static int lzip_getattr(vfile *vf, struct avstat *buf, int attrmask)
{
    int res;
    struct lziphandle *fil = (struct lziphandle *) vf->data;
    struct lzipnode *nod = fil->node;
    avoff_t size;
    const int basemask = AVA_MODE | AVA_UID | AVA_GID | AVA_MTIME | AVA_ATIME | AVA_CTIME;
    struct lzipcache *zc;
    struct cacheobj *cobj;

    res = av_fgetattr(fil->base, buf, basemask);
    if(res < 0)
        return res;

    AV_LOCK(fil->node->lock);
    zc = lzip_getcache(vf->mnt->base, fil->node);
    cobj = fil->node->cache;
    av_ref_obj(cobj);
    AV_UNLOCK(fil->node->lock);

    if((attrmask & (AVA_SIZE | AVA_BLKCNT)) != 0) {
        res = av_lzipfile_size(fil->zfil, zc, &size);
        if(res == 0 && size == -1) {
            fil->zfil = av_lzipfile_new(fil->base);
            res = av_lzipfile_size(fil->zfil, zc, &size);
        }
        if(res < 0) {
            av_unref_obj(zc);
            av_unref_obj(cobj);

            return res;
        }

        buf->size = size;
        buf->blocks = AV_BLOCKS(buf->size);
    }

    buf->mode &= ~(07000);
    buf->blksize = 4096;
    buf->dev = vf->mnt->avfs->dev;
    buf->ino = nod->ino;
    buf->nlink = 1;
    
    av_unref_obj(zc);
    av_unref_obj(cobj);

    return 0;
}

extern int av_init_module_ulzip(struct vmodule *module);

int av_init_module_ulzip(struct vmodule *module)
{
    int res;
    struct avfs *avfs;
    struct ext_info ulzip_exts[3];

    ulzip_exts[0].from = ".tar.lz",  ulzip_exts[0].to = ".tar";
    ulzip_exts[1].from = ".lz",  ulzip_exts[1].to = NULL;
    ulzip_exts[2].from = NULL;

    res = av_new_avfs("ulzip", ulzip_exts, AV_VER, AVF_NOLOCK, module, &avfs);
    if(res < 0)
        return res;

    avfs->lookup   = lzip_lookup;
    avfs->access   = lzip_access;
    avfs->open     = lzip_open;
    avfs->close    = lzip_close; 
    avfs->read     = lzip_read;
    avfs->getattr  = lzip_getattr;

    av_add_avfs(avfs);

    return 0;
}
