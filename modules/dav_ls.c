/* 
   ls for AVFS DAV support.
  
   Most of this file is taken from ls.c in cadaver, which has the
   following copyright notice:

   'ls' for cadaver
   Copyright (C) 2000-2001, Joe Orton <joe@orton.demon.co.uk>, 
   except where otherwise indicated.
                                   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "filebuf.h"

#include <time.h>
#include <string.h>
#include <stdlib.h>
#include "dav.h"
#include <neon/ne_dates.h>

struct fetch_context {
  struct av_dav_conn *conn;
  struct av_dav_resource **list;
  const char *target; /* Request-URI of the PROPFIND */
  unsigned int include_target; /* Include resource at href */
};  

static const ne_propname props[] = {
  { "DAV:", "getcontentlength" },
  { "DAV:", "getlastmodified" },
  { "http://apache.org/dav/props/", "executable" },
  { "DAV:", "resourcetype" },
  { NULL }
};

static int compare_resource(const struct av_dav_resource *r1, 
              const struct av_dav_resource *r2)
{
  /* Sort errors first, then collections, then alphabetically */
  if (r1->type == resr_error) {
    return -1;
  } else if (r2->type == resr_error) {
    return 1;
  } else if (r1->type == resr_collection) {
    if (r2->type != resr_collection) {
      return -1;
    } else {
      return strcmp(r1->uri, r2->uri);
    }
  } else {
    if (r2->type != resr_collection) {
      return strcmp(r1->uri, r2->uri);
    } else {
      return 1;
    }
  }
}

static void results(void *userdata, const ne_uri *uri,
          const ne_prop_result_set *set)
{
  struct fetch_context *ctx = userdata;
  struct av_dav_resource *current, *previous, *newres;
  const char *clength, *modtime, *isexec, *abspath;
  const ne_status *status = NULL;

  av_log (AVLOG_DEBUG, "DAV URI: %s", uri->path);

  newres = ne_propset_private(set);
  abspath = uri->path;

  if (ne_path_compare(ctx->target, abspath) == 0 && !ctx->include_target) {
    /* This is the target URI, skip it */
    av_free(newres);
    return;
  }

  newres->uri = ne_strdup(abspath);

  // flat attributes are those declined in the xml start_element
  // handler.
  clength = ne_propset_value(set, &props[0]);  
  modtime = ne_propset_value(set, &props[1]);
  isexec = ne_propset_value(set, &props[2]);

  if (clength == NULL) {
      status = ne_propset_status(set, &props[0]);
  }

  if (modtime == NULL) {
      status = ne_propset_status(set, &props[1]);
  }

  if (newres->type == resr_normal && status) {
    /* It's an error! */
    newres->error_status = status->code;

    /* Special hack for Apache 1.3/mod_dav */
    if (strcmp(status->reason_phrase, "status text goes here") == 0) {
      const char *desc;
      if (status->code == 401) {
        desc = ("Authorization Required");
      } else if (status->klass == 3) {
        desc = ("Redirect");
      } else if (status->klass == 5) {
        desc = ("Server Error");
      } else {
        desc = ("Unknown Error");
      }
      newres->error_reason = ne_strdup(desc);
    } else {
      newres->error_reason = ne_strdup(status->reason_phrase);
    }
    newres->type = resr_error;
  }

  if (isexec && strcasecmp(isexec, "T") == 0) {
    newres->is_executable = 1;
  } else {
    newres->is_executable = 0;
  }

  if (modtime) {
      newres->modtime = ne_httpdate_parse(modtime);
  }

  if (clength) {
      newres->size = strtol(clength, NULL, 10);
  }

  for (current = *ctx->list, previous = NULL; current != NULL; 
     previous = current, current=current->next) {
    if (compare_resource(current, newres) >= 0) {
      break;
    }
  }
  if (previous) {
    previous->next = newres;
  } else {
    *ctx->list = newres;
  }
  newres->next = current;
}

int start_element(void *userdata, int parent,
                  const char *nspace, const char *name,
                  const char **atts)
{
    ne_propfind_handler *pfh = userdata;
    struct av_dav_resource *r = ne_propfind_current_private(pfh);

    if (parent == 2) {
        // resourcetype
        if (strcmp(name, "collection") == 0) {
            r->type = resr_collection;
        }
    } else {
        if (strcmp(name, "resourcetype") == 0) {
            return 2;
        }
    }

    return NE_XML_DECLINE;
}

int data_element(void *userdata, int state,
                 const char *cdata, size_t len)
{
    return 0;
}

int end_element(void *userdata, int state, 
                const char *nspace, const char *name)
{
    return 0;
}

void free_resource(struct av_dav_resource *res)
{
  ne_free(res->uri);
  ne_free(res->error_reason);
  av_free(res);
}

void free_resource_list(struct av_dav_resource *res)
{
  struct av_dav_resource *next;
  for (; res != NULL; res = next) {
    next = res->next;
    free_resource(res);
  }
}

static void *create_private(void *userdata, const ne_uri *uri)
{
    return av_calloc(sizeof(struct av_dav_resource));
}

int fetch_resource_list(struct av_dav_conn *conn,
                const char *uri, int depth, int include_target,
                struct av_dav_resource **reslist)
{
  ne_propfind_handler *pfh = ne_propfind_create(conn->sesh, uri, depth);
  int ret;
  struct fetch_context ctx = {0};
  
  *reslist = NULL;
  ctx.conn = conn;
  ctx.list = reslist;
  ctx.target = uri;
  ctx.include_target = include_target;

  ne_xml_push_handler(ne_propfind_get_parser(pfh),
                      start_element,
                      data_element,
                      end_element,
                      pfh);

  ne_propfind_set_private(pfh,
                          create_private,
                          NULL,
                          NULL);

  ret = ne_propfind_named(pfh, props, results, &ctx);

  ne_propfind_destroy(pfh);

  return ret;
}
