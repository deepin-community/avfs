/*  
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.
*/

#include "filecache.h"
#include "internal.h"
#include "exit.h"

// keep this many elements in the case
#define FILECACHE_MAX_SIZE 50

// and remove any additional elements if they are older than this number of seconds
#define FILECACHE_MAX_AGE ( 10 * 60 )

struct filecache {
    struct filecache *next;
    struct filecache *prev;
    
    char *key;
    void *obj;

    time_t last_access;
};

static struct filecache fclist;
static int fclist_len;
static AV_LOCK_DECL(fclock);

static void filecache_remove(struct filecache *fc)
{
    struct filecache *prev = fc->prev;
    struct filecache *next = fc->next;

    prev->next = next;
    next->prev = prev;

    fclist_len--;
}

static void filecache_insert(struct filecache *fc)
{
    struct filecache *prev = &fclist;
    struct filecache *next = fclist.next;
    
    prev->next = fc;
    next->prev = fc;
    fc->prev = prev;
    fc->next = next;

    fclist_len++;

    struct timespec tv;
    if ( clock_gettime( CLOCK_MONOTONIC, &tv ) == 0 ) {
        fc->last_access = tv.tv_sec;
    } else {
        fc->last_access = 0;
    }
}

static void filecache_delete(struct filecache *fc)
{
    av_log(AVLOG_DEBUG, "FILECACHE: delete <%s>", fc->key);
    filecache_remove(fc);

    av_unref_obj(fc->obj);
    av_free(fc->key);
    av_free(fc);
}

static void filecache_check_limits(void)
{
    struct timespec now;
    if ( clock_gettime( CLOCK_MONOTONIC, &now ) != 0 ) {
        now.tv_sec = 0;
    }

    while (fclist_len > FILECACHE_MAX_SIZE &&
           fclist.prev != &fclist) {

        if (now.tv_sec == 0 ||
            (now.tv_sec != 0 && (int)(now.tv_sec - fclist.prev->last_access) > FILECACHE_MAX_AGE)) {
            filecache_delete(fclist.prev);
        } else {
            break;
        }
    }
}

static struct filecache *filecache_find(const char *key)
{
    struct filecache *fc;

    filecache_check_limits();

    for(fc = fclist.next; fc != &fclist; fc = fc->next) {
        if(strcmp(fc->key, key) == 0)
            break;
    }

    if(fc->obj == NULL)
        return NULL;

    return fc;
}

void *av_filecache_get(const char *key)
{
    struct filecache *fc;
    void *obj = NULL;
    
    AV_LOCK(fclock);
    fc = filecache_find(key);
    if(fc != NULL) {
        filecache_remove(fc);
        filecache_insert(fc);
        obj = fc->obj;
        av_ref_obj(obj);
    }
    AV_UNLOCK(fclock);

    return obj;
}

void av_filecache_set(const char *key, void *obj)
{
    struct filecache *oldfc;
    struct filecache *fc;

    if(obj != NULL) {
        AV_NEW(fc);
        fc->key = av_strdup(key);
        fc->obj = obj;
        av_ref_obj(obj);
    }
    else
        fc = NULL;

    AV_LOCK(fclock);
    oldfc = filecache_find(key);
    if(oldfc != NULL)
        filecache_delete(oldfc);
    if(fc != NULL) {
        av_log(AVLOG_DEBUG, "FILECACHE: insert <%s>", key);
        filecache_insert(fc);
    }
    AV_UNLOCK(fclock);
}

static void destroy_filecache()
{
    AV_LOCK(fclock);
    while(fclist.next != &fclist)
        filecache_delete(fclist.next);
    AV_UNLOCK(fclock);
}

void av_init_filecache()
{
    fclist.next = &fclist;
    fclist.prev = &fclist;
    fclist.obj = NULL;
    fclist.key = NULL;

    fclist_len = 0;
    
    av_add_exithandler(destroy_filecache);
}


int av_filecache_getkey(ventry *ve, char **resp)
{
    int res;
    char *key;

    res = av_generate_path(ve->mnt->base, &key);
    if(res < 0)
        return res;

    key = av_stradd(key, AVFS_SEP_STR, ve->mnt->avfs->name, NULL);

    *resp = key;
    return 0;
}
