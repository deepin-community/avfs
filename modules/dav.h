#ifndef INCLUDED_DAV_H
#define INCLUDED_DAV_H 1

#include "passwords.h"

#include <neon/ne_alloc.h>
#include <neon/ne_request.h>
#include <neon/ne_basic.h>
#include <neon/ne_props.h>
#include <neon/ne_uri.h>

/* --------------------------------------------------------------------- */

#define DAV_PARAM_SEP           ':'
#define AV_MAX_DAV_CONNS        128

/* --------------------------------------------------------------------- */

/**
 * The DAV connection structure.
 */
struct av_dav_conn {
  ne_session *sesh;
  char *user;
  char *password;
  ne_uri uri;
  int isbusy;

    struct davdata *data; // backlink to global data, needed for
                          // password management
};

struct av_dav_fdidat {
  ne_uri *base_uri;
  char *tmpname;
  char *remote;
  int rdonly;
  int cursize;
  int error;
};

struct davdata {
  struct av_dav_conn allconns[AV_MAX_DAV_CONNS];
  struct pass_session sessions;
};

/**
 * DAV properties: "resources", ie. files or directories in DAVspeak.
 */
enum av_dav_resource_type {
    resr_normal = 0,
    resr_collection,
    resr_reference,
    resr_error
};

struct av_dav_resource {
    char *uri;
    enum av_dav_resource_type type;
    size_t size;
    time_t modtime;
    int is_executable;
    char *error_reason; /* error string returned for this resource */
    int error_status; /* error status returned for this resource */
    struct av_dav_resource *next;
};

extern void free_resource( struct av_dav_resource *res );
extern void free_resource_list( struct av_dav_resource *res );

/* --------------------------------------------------------------------- */

extern int fetch_resource_list(struct av_dav_conn *conn,
                const char *uri, int depth, int include_target,
                struct av_dav_resource **reslist);

/* --------------------------------------------------------------------- */

#endif
