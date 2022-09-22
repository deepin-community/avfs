/*  
    AVFS: A Virtual File System Library
    Copyright (C) 2018  Ralf Hoffmann <ralf@boomerangsworld.de>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    UZSTD module (based on UBZ2 module)
*/

#include "version.h"

#include "zstdfile.h"
#include "filecache.h"
#include "oper.h"
#include "version.h"

struct zstdnode {
    struct avstat sig;
    struct zstdcache *cache;
    avino_t ino;
};

struct zstdhandle {
    struct zstdfile *zfil;
    vfile *base;
    struct zstdnode *node;
};


static void zstdnode_destroy(struct zstdnode *nod)
{
    av_unref_obj(nod->cache);
}

static struct zstdnode *zstd_new_node(ventry *ve, struct avstat *stbuf)
{
    struct zstdnode *nod;

    AV_NEW_OBJ(nod, zstdnode_destroy);
    nod->sig = *stbuf;
    nod->cache = av_zstdcache_new();
    nod->ino = av_new_ino(ve->mnt->avfs);
    
    return nod;
}

static int zstd_same(struct zstdnode *nod, struct avstat *stbuf)
{
    if(nod->sig.ino == stbuf->ino &&
       nod->sig.dev == stbuf->dev &&
       nod->sig.size == stbuf->size &&
       AV_TIME_EQ(nod->sig.mtime, stbuf->mtime))
        return 1;
    else
        return 0;
}

static struct zstdnode *zstd_do_get_node(ventry *ve, const char *key,
                                         struct avstat *stbuf)
{
    static AV_LOCK_DECL(lock);
    struct zstdnode *nod;

    AV_LOCK(lock);
    nod = (struct zstdnode *) av_filecache_get(key);
    if(nod != NULL) {
        if(!zstd_same(nod, stbuf)) {
            av_unref_obj(nod);
            nod = NULL;
        }
    }
    
    if(nod == NULL) {
        nod =  zstd_new_node(ve, stbuf);
        av_filecache_set(key, nod);
    }
    AV_UNLOCK(lock);

    return nod;
}

static int zstd_getnode(ventry *ve, vfile *base, struct zstdnode **resp)
{
    int res;
    struct avstat stbuf;
    const int attrmask = AVA_INO | AVA_DEV | AVA_SIZE | AVA_MTIME;
    struct zstdnode *nod;
    char *key;

    res = av_fgetattr(base, &stbuf, attrmask);
    if(res < 0)
        return res;

    res = av_filecache_getkey(ve, &key);
    if(res < 0)
        return res;

    nod = zstd_do_get_node(ve, key, &stbuf);

    av_free(key);

    *resp = nod;
    return 0;
}

static int zstd_lookup(ventry *ve, const char *name, void **newp)
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

static int zstd_access(ventry *ve, int amode)
{
    return av_access(ve->mnt->base, amode);
}

static int zstd_open(ventry *ve, int flags, avmode_t mode, void **resp)
{
    int res;
    vfile *base;
    struct zstdnode *nod;
    struct zstdhandle *fil;

    if(flags & AVO_DIRECTORY)
        return -ENOTDIR;

    if(AV_ISWRITE(flags))
        return -EROFS;

    res = av_open(ve->mnt->base, AVO_RDONLY, 0, &base);
    if(res < 0)
        return res;

    res = zstd_getnode(ve, base, &nod);
    if(res < 0) {
        av_close(base);
        return res;
    }

    AV_NEW(fil);
    if((flags & AVO_ACCMODE) != AVO_NOPERM)
        fil->zfil = av_zstdfile_new(base);
    else
        fil->zfil = NULL;

    fil->base = base;
    fil->node = nod;
    
    *resp = fil;
    return 0;
}

static int zstd_close(vfile *vf)
{
    struct zstdhandle *fil = (struct zstdhandle *) vf->data;

    av_unref_obj(fil->zfil);
    av_unref_obj(fil->node);
    av_close(fil->base);
    av_free(fil);

    return 0;
}

static avssize_t zstd_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct zstdhandle *fil = (struct zstdhandle *) vf->data;
 
    res = av_zstdfile_pread(fil->zfil, fil->node->cache, buf, nbyte, vf->ptr);
    if(res > 0)
        vf->ptr += res;

    return res;
}

static int zstd_getattr(vfile *vf, struct avstat *buf, int attrmask)
{
    int res;
    struct zstdhandle *fil = (struct zstdhandle *) vf->data;
    struct zstdnode *nod = fil->node;
    avoff_t size;
    const int basemask = AVA_MODE | AVA_UID | AVA_GID | AVA_MTIME | AVA_ATIME | AVA_CTIME;

    res = av_fgetattr(fil->base, buf, basemask);
    if(res < 0)
        return res;

    if((attrmask & (AVA_SIZE | AVA_BLKCNT)) != 0) {
        res = av_zstdfile_size(fil->zfil, fil->node->cache, &size);
        if(res == 0 && size == -1) {
            fil->zfil = av_zstdfile_new(fil->base);
            res = av_zstdfile_size(fil->zfil, fil->node->cache, &size);
        }
        if(res < 0)
            return res;

        buf->size = size;
        buf->blocks = AV_BLOCKS(buf->size);
    }

    buf->mode &= ~(07000);
    buf->blksize = 4096;
    buf->dev = vf->mnt->avfs->dev;
    buf->ino = nod->ino;
    buf->nlink = 1;
    
    return 0;
}

extern int av_init_module_uzstd(struct vmodule *module);

int av_init_module_uzstd(struct vmodule *module)
{
    int res;
    struct avfs *avfs;
    struct ext_info uzstd_exts[4];

    uzstd_exts[0].from = ".tar.zst",  uzstd_exts[0].to = ".tar";
    uzstd_exts[1].from = ".tzst",  uzstd_exts[1].to = ".tar";
    uzstd_exts[2].from = ".zst",  uzstd_exts[2].to = NULL;
    uzstd_exts[3].from = NULL;

    res = av_new_avfs("uzstd", uzstd_exts, AV_VER, AVF_NOLOCK, module, &avfs);
    if(res < 0)
        return res;

    avfs->lookup   = zstd_lookup;
    avfs->access   = zstd_access;
    avfs->open     = zstd_open;
    avfs->close    = zstd_close; 
    avfs->read     = zstd_read;
    avfs->getattr  = zstd_getattr;

    av_add_avfs(avfs);

    return 0;
}
