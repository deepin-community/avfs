/*
    AVFS: A Virtual File System Library
    Copyright (C) 1998  Miklos Szeredi <miklos@szeredi.hu>
    
    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    RAR module
    Copyright (C) 1998 David Hanak (dhanak@inf.bme.hu)
*/

#include "archive.h"
#include "realfile.h"
#include "prog.h"
#include "oper.h"
#include "version.h"

#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

#define DOS_DIR_SEP_CHAR  '\\'

enum rar_format { RAR,
                  RAR50
};

static avbyte good_marker_head[] = 
{ 0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00 };

#define LONG_HEAD_SIZE      11
#define SHORT_HEAD_SIZE      7
#define FILE_HEAD_SIZE      21
#define MARKER_HEAD_SIZE (sizeof(good_marker_head)/sizeof(avbyte))

typedef avbyte block_header[LONG_HEAD_SIZE];
typedef avbyte file_header[FILE_HEAD_SIZE];

#define BI(ptr, i)  ((avbyte) (ptr)[i])
#define BYTE(ptr)  (BI(ptr,0))
#define DBYTE(ptr) ((avushort)(BI(ptr,0) | (BI(ptr,1)<<8)))
#define QBYTE(ptr) ((avuint)(BI(ptr,0) | (BI(ptr,1)<<8) | \
                   (BI(ptr,2)<<16) | (BI(ptr,3)<<24)))
#define QQBYTE(ptr) ((avuquad)((avuquad)BI(ptr,0) | ((avuquad)BI(ptr,1)<<8) | \
                               ((avuquad)BI(ptr,2)<<16) | ((avuquad)BI(ptr,3)<<24) | \
                               ((avuquad)BI(ptr,4)<<32) | ((avuquad)BI(ptr,5)<<40) | \
                               ((avuquad)BI(ptr,6)<<48) | ((avuquad)BI(ptr,7)<<56)))

#define bh_CRC(bh)      DBYTE(bh     )
#define bh_type(bh)     BYTE (bh +  2)
#define bh_flags(bh)    DBYTE(bh +  3)
#define bh_headsize(bh) DBYTE(bh +  5)
#define bh_addsize(bh)  QBYTE(bh +  7)
#define bh_size(bh)     (bh_headsize(bh) + bh_addsize(bh))

#define fh_origsize(fh) QBYTE(fh     )
#define fh_hostos(fh)   BYTE (fh +  4)
#define fh_CRC(fh)      QBYTE(fh +  5)
#define fh_time(fh)     QBYTE(fh +  9)
#define fh_version(fh)  BYTE (fh + 13)
#define fh_method(fh)   BYTE (fh + 14)
#define fh_namelen(fh)  DBYTE(fh + 15)
#define fh_attr(fh)     QBYTE(fh + 17)

#define dos_ftsec(ft)   (int)( 2 * ((ft >>  0) & 0x1F))
#define dos_ftmin(ft)   (int)(     ((ft >>  5) & 0x3F))
#define dos_fthour(ft)  (int)(     ((ft >> 11) & 0x1F))
#define dos_ftday(ft)   (int)(     ((ft >> 16) & 0x1F))
#define dos_ftmonth(ft) (int)(-1 + ((ft >> 21) & 0x0F))
#define dos_ftyear(ft)  (int)(80 + ((ft >> 25) & 0x7F))

/* Block types */
#define B_MARKER             0x72
#define B_MAIN               0x73
#define B_FILE               0x74
#define B_COMMENT            0x75
#define B_EXTRA_INFO         0x76
#define B_SUB                0x77
#define B_RECOVERY           0x78

/* Block flags */
#define FB_OUTDATED        0x4000
#define FB_WITH_BODY       0x8000

/* Archive flags */
#define FA_IS_VOLUME         0x01
#define FA_WITH_COMMENT      0x02
#define FA_IS_SOLID          0x04
#define FA_WITH_AUTHENTICITY 0x20

/* File block flags */
#define FF_CONT_FROM_PREV    0x01
#define FF_CONT_IN_NEXT      0x02
#define FF_WITH_PASSWORD     0x04
#define FF_WITH_COMMENT      0x08
#define FF_IS_SOLID          0x10

/* Compression methods */
#define M_STORE              0x30
#define M_FASTEST            0x31
#define M_FAST               0x32
#define M_NORMAL             0x33
#define M_GOOD               0x34
#define M_BEST               0x35

/* Archiving OS */
#define OS_MSDOS                0
#define OS_OS2                  1
#define OS_WIN32                2
#define OS_UNIX                 3

#define CRC_START     0xFFFFFFFFUL
#define CRC_INIT      0xEDB88320UL

#define CRC_TABLESIZE 256
static avuint CRC_table[CRC_TABLESIZE];

/* some rar 5 header values (not complete, just what is necessary for
   the features */
enum { RAR5_HEADER_TYPE_MAIN_ARCHIVE_HEADER = 1,
       RAR5_HEADER_TYPE_FILE_HEADER = 2,
       RAR5_HEADER_TYPE_END_OF_ARCHIVE = 5 };
enum { RAR5_HEADER_FLAGS_EXTRA_PRESENT = 1,
       RAR5_HEADER_FLAGS_DATA_PRESENT = 2 };
enum { RAR5_HEADER_FILE_HEADER_FILE_FLAGS_DIRECTORY_OBJECT = 1,
       RAR5_HEADER_FILE_HEADER_FILE_FLAGS_UNIX_TIME_PRESENT = 2,
       RAR5_HEADER_FILE_HEADER_FILE_FLAGS_CRC_PRESENT = 4,
       RAR5_HEADER_FILE_HEADER_FILE_FLAGS_UNPACKED_SIZE_UNKNOWN = 8 };
enum { RAR5_HEADER_FILE_HEADER_HOST_OS_WINDOWS = 0,
       RAR5_HEADER_FILE_HEADER_HOST_OS_UNIX = 1 };
enum { RAR5_HEADER_FILE_HEADER_EXTRA_TYPE_FILE_TIME = 3 };
enum { RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_UNIX_TIME = 0x01,
       RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_MTIME_PRESENT = 0x02,
       RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_CTIME_PRESENT = 0x04,
       RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_ATIME_PRESENT = 0x08,
       RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_NSEC_PRECISION = 0x10 };

struct rarnode {
    avushort flags;
    avbyte hostos;
    avbyte packer_version;
    avbyte method;
    char *path;
};

struct rar_entinfo {
    char *name;
    char *linkname;
    avoff_t datastart;
    block_header bh;
    file_header fh;
};

struct rar5_entinfo {
    char *name;
    char *linkname;
    avbyte is_dir;
    avoff_t size;
    avtimestruc_t mtime;
    avtimestruc_t atime;
    avtimestruc_t ctime;
    avmode_t mode;
};

struct rarfile {
    char *tmpfile;
    int fd;
};

static void initCRC(void)
{
    int i, j;
    avuint c;
  
    for (i = 0; i < CRC_TABLESIZE; i++)
    {
        for (c = i, j = 0; j < 8; j++)
            c = (c & 1) ? (c >> 1) ^ CRC_INIT : (c >> 1);
        CRC_table[i] = c;
    }
}

static avuint CRC_byte(avuint crc, avbyte byte)
{
    return CRC_table[(avbyte)crc ^ byte] ^ (crc >> 8);
}

static avuint CRC_string(avuint crc, avbyte *buf, long size)
{
    long i;

    for (i = 0; i < size; i++)
        crc = CRC_byte(crc, buf[i]);
    return crc;
}

static int read_block_header(vfile *vf, block_header bh, int all)
{
    int res;
    int size = SHORT_HEAD_SIZE;
    int i;

    for(i = SHORT_HEAD_SIZE; i < LONG_HEAD_SIZE; i++) bh[i] = 0;

    if(all)
        res = av_read_all(vf, (char*)bh, SHORT_HEAD_SIZE);
    else
        res = av_read(vf, (char*)bh, SHORT_HEAD_SIZE);
    if(res < 0)
        return res;
    if(res < SHORT_HEAD_SIZE)
        return 0;

    if ((bh_flags(bh) & FB_WITH_BODY) != 0) {
        res = av_read_all(vf, (char*) ( bh+SHORT_HEAD_SIZE ), 4);
        if(res < 0)
            return res;

        size += 4;
    }

    return size;
}

static int read_marker_block(vfile *vf, enum rar_format *format)
{
    int res;
    avbyte buf[MARKER_HEAD_SIZE], *pos = buf;
    int readsize = MARKER_HEAD_SIZE;

    /* An SFX module starts with the extraction header. Skip that part by
       searching for the marker head. */
    while(1) {
        res = av_read_all(vf, (char*)( buf + MARKER_HEAD_SIZE - readsize ), readsize);
        if(res < 0)
            return res;

        if (memcmp(buf, good_marker_head, MARKER_HEAD_SIZE - 1) == 0) {
            if (buf[6] == 0) {
                // rar format 1.5
                *format = RAR;
                return 0;
            } else if (buf[6] == 1) {
                // rar format 5.0
                *format = RAR50;

                // rar 5.0 uses one additional byte
                res = av_read_all(vf, (char*)buf, 1);
                if(res < 0)
                    return res;

                if (buf[0] != 0) {
                    return -EINVAL;
                }

                return 0;
            } else if (buf[6] == 2) {
                // rar future format
                return -ENOTSUP;
            }
        }

        pos = memchr(buf + 1, good_marker_head[0], MARKER_HEAD_SIZE-1);
        if (pos == NULL) readsize = MARKER_HEAD_SIZE;
        else {
            readsize = pos - buf;
            memmove(buf, pos, MARKER_HEAD_SIZE - readsize);
        }
    }
    return 0; /* Just to avoid warnings. Never reaches this line. */
}

static int read_archive_header(vfile *vf)
{
    int res;
    block_header main_head;
    avuint crc;
    avbyte tmpbuf[6];
    int headlen;

    headlen = read_block_header(vf, main_head, 1);
    if(headlen < 0)
        return headlen;

    if (bh_type(main_head) != B_MAIN) {
        av_log(AVLOG_ERROR, "URAR: Bad archive header");
        return -EIO;
    }

    crc = CRC_string(CRC_START, main_head + 2, headlen - 2);

    /* Read reserved bytes. */
    res = av_read_all(vf, (char*)tmpbuf, 6);
    if(res < 0)
        return res;
    crc = CRC_string(crc, tmpbuf, 6);

    if ((avushort)~crc != bh_CRC(main_head)) {
        av_log(AVLOG_ERROR, "URAR: Bad archive header CRC");
        return -EIO;
    }

    av_lseek(vf, bh_size(main_head) - headlen - 6, AVSEEK_CUR);

    return 0;
}

static void conv_tolower(char *s)
{
    for(; *s; s++) *s = tolower((int) *s);
}


static void dos2unix_path(char *path)
{
    char *pos = path;

    while((pos = strchr(pos, DOS_DIR_SEP_CHAR)) != NULL)
        *pos = '/';
}

static avtime_t dos2unix_time(avuint dt)
{
    struct avtm ut;

    ut.sec = dos_ftsec(dt);
    ut.min = dos_ftmin(dt);
    ut.hour = dos_fthour(dt);
    ut.day = dos_ftday(dt);
    ut.mon = dos_ftmonth(dt);
    ut.year = dos_ftyear(dt);

    return av_mktime(&ut);
}

static avmode_t dos2unix_attr(avuint da, avmode_t archmode)
{
    avmode_t mode = (archmode & 0666);
    if (da & 0x01) mode = mode & ~0222;
    if (da & 0x10) mode = mode | ((mode & 0444) >> 2) | AV_IFDIR;
    else mode |= AV_IFREG;

    return mode;
}

static void rarnode_delete(struct rarnode *info)
{
    av_free(info->path);
}

static avmode_t rar_get_mode(struct rar_entinfo *ei, avmode_t origmode)
{
    if (bh_flags(ei->bh) & FF_WITH_PASSWORD)
        return AV_IFREG; /* FIXME */
    else {
        if (fh_hostos(ei->fh) == OS_UNIX)
            return fh_attr(ei->fh);
        else 
            return dos2unix_attr(fh_attr(ei->fh), origmode);
    }
}

static void fill_rarentry(struct archive *arch, struct entry *ent,
                         struct rar_entinfo *ei)
{
    struct rarnode *info;
    struct archnode *nod;
    int isdir = AV_ISDIR(rar_get_mode(ei, 0));

    nod = av_arch_new_node(arch, ent, isdir);

    nod->st.mode = rar_get_mode(ei, nod->st.mode);
    nod->st.mtime.sec = dos2unix_time(fh_time(ei->fh));
    nod->st.mtime.nsec = 0;
    nod->st.atime = nod->st.mtime;
    nod->st.ctime = nod->st.mtime;
    nod->st.size = fh_origsize(ei->fh);
    nod->st.blocks = AV_BLOCKS(nod->st.size);
    nod->st.blksize = 4096;

    nod->offset = ei->datastart;
    if(fh_method(ei->fh) == M_STORE)
        nod->realsize = fh_origsize(ei->fh);
    else
        nod->realsize = 0;

    nod->linkname = av_strdup(ei->linkname);

    AV_NEW_OBJ(info, rarnode_delete);
    nod->data = info;

    info->flags = bh_flags(ei->bh);
    info->hostos = fh_hostos(ei->fh);
    info->packer_version = fh_version(ei->fh);
    info->method = fh_method(ei->fh);
    info->path = av_strdup(ei->name);
}

static void insert_rarentry(struct archive *arch, struct rar_entinfo *ei)
{
    struct entry *ent;
    int entflags = 0;
    char *path = ei->name;

    dos2unix_path(path);

    if(fh_hostos(ei->fh) == OS_MSDOS) {
        conv_tolower(path);
        entflags |= NSF_NOCASE;
    }

    ent = av_arch_create(arch, path, entflags);
    if(ent == NULL)
        return;

    fill_rarentry(arch, ent, ei);
    av_unref_obj(ent);
}

static void fill_rar5entry(struct archive *arch, struct entry *ent,
                           struct rar5_entinfo *ei)
{
    struct rarnode *info;
    struct archnode *nod;

    nod = av_arch_new_node(arch, ent, ei->is_dir);

    nod->st.mode = ei->mode;
    nod->st.mtime = ei->mtime;
    nod->st.atime = ei->atime;
    nod->st.ctime = ei->ctime;
    nod->st.size = ei->size;
    nod->st.blocks = AV_BLOCKS(nod->st.size);
    nod->st.blksize = 512;

    nod->offset = 0;
    nod->realsize = 0;

    nod->linkname = NULL;

    AV_NEW_OBJ(info, rarnode_delete);
    nod->data = info;

    info->flags = 0;
    info->hostos = 0;
    info->packer_version = 0;
    info->method = 0;
    info->path = av_strdup(ei->name);
}

static void insert_rar5entry(struct archive *arch, struct rar5_entinfo *ei)
{
    struct entry *ent;
    int entflags = 0;
    char *path = ei->name;

    ent = av_arch_create(arch, path, entflags);
    if(ent == NULL) {
        return;
    }

    fill_rar5entry(arch, ent, ei);
    av_unref_obj(ent);
}

static int crc_additional_header(vfile *vf, struct rar_entinfo *ei, int bytes_crcd, avuint *crc)
{
    /* In the header there are some optional entries (e.g. salt, exttime; see arcread.ccp::ReadHeader
     * from unrar package). We need to use these bytes for the CRC.
     * Currently this optional stuff is not supported and I don't want to
     * add additional code to handle these information so I just read the
     * remaining bytes up to bh_headsize
     *
     * TODO: The salt is needed for crypted files which are not supported right now
     *       so this is not a problem.
     *       But perhaps it is a good idea to support the additional time information.
     */
    int res, tlen = bytes_crcd;
    avbyte *tempbuf;
    
    tlen = bh_headsize(ei->bh) - 2 - tlen;
    
    if(tlen > 0) {
        tempbuf = av_malloc(tlen);
	res = av_read_all(vf, (char*)tempbuf, tlen);
	if(res < 0) {
	    av_free(tempbuf);
	    return res;
	}
	*crc = CRC_string(*crc, tempbuf, tlen);
	av_free(tempbuf);
    } else if(tlen < 0) {
        return -EIO;
    }
    return 0;
}

static int read_rarentry(vfile *vf, struct rar_entinfo *ei)
{
    int res;
    block_header ch;
    avuint crc;

    if (bh_size(ei->bh) < LONG_HEAD_SIZE + FILE_HEAD_SIZE) {
        av_log(AVLOG_ERROR, "URAR: bad header");
        return -EIO;
    }
            
    res = av_read_all(vf, (char*)( ei->fh ), FILE_HEAD_SIZE);
    if(res < 0)
        return res;

    ei->name = av_malloc(fh_namelen(ei->fh)+1);
    res = av_read_all(vf, ei->name, fh_namelen(ei->fh));
    if(res < 0)
        return res;
    ei->name[fh_namelen(ei->fh)] = '\0';
    
    crc = CRC_string(CRC_START, ei->bh + 2, LONG_HEAD_SIZE - 2);
    crc = CRC_string(crc, ei->fh, FILE_HEAD_SIZE);
    crc = CRC_string(crc, (avbyte*)( ei->name ), fh_namelen(ei->fh));

    if(crc_additional_header(vf, ei,
			     LONG_HEAD_SIZE - 2 + FILE_HEAD_SIZE + fh_namelen(ei->fh),
			     &crc) != 0) {
        av_log(AVLOG_ERROR, "URAR: bad header");
        return -EIO;
    }
    
    if ((avushort)~crc != bh_CRC(ei->bh)) {
        av_log(AVLOG_ERROR, "URAR: bad CRC");
        return -EIO;
    }
    
    if ((bh_flags(ei->bh) & FF_WITH_COMMENT) != 0) {
        res = read_block_header(vf, ch, 1);
        if(res < 0)
            return res;

        av_lseek(vf, bh_size(ch) - res, AVSEEK_CUR);
    }
    
    if(fh_hostos(ei->fh) == OS_UNIX && AV_ISLNK(fh_attr(ei->fh))) {
        ei->linkname = av_malloc(fh_origsize(ei->fh) + 1);
        res = av_read_all(vf, ei->linkname, fh_origsize(ei->fh));
        if(res < 0)
            return res;

        ei->linkname[fh_origsize(ei->fh)] = '\0';
    }
    
    return 0;
}

// up to 10 bytes, 7 bits of data per byte, bit 7 == 1 indicates
// continuation. Encoding is in little endian
static int read_vint(vfile *vf, avuquad *result, avuint *crc)
{
    int read_res;
    int count = 0;
    avbyte buf[1];
    avuquad res = 0;

    for (count = 0; count < 10; count++) {
        read_res = av_read_all(vf, (char*)buf, 1);
        if (read_res < 0) {
            av_log(AVLOG_ERROR, "URAR: out of data during vint parsing");
            return read_res;
        }
        *crc = CRC_byte(*crc, buf[0]);

        res |= (buf[0] & 0x7f) << (7 * count);
        if ((buf[0] & 0x80) == 0) {
            *result = res;
            return 0;
        }
    }

    av_log(AVLOG_ERROR, "URAR: invalid vint");
    
    return -EINVAL;
}

static int read_uint32(vfile *vf, avuint *result, avuint *crc)
{
    avbyte buf[4];
    int res;

    res = av_read_all(vf, (char*)buf, 4);
    if (res < 0) {
        return res;
    }

    *result = QBYTE(buf);

    if (crc) {
        *crc = CRC_string(*crc, buf, 4);
    }

    return 0;
}

static int read_uint64(vfile *vf, avuquad *result, avuint *crc)
{
    avbyte buf[8];
    int res;

    res = av_read_all(vf, (char*)buf, 8);
    if (res < 0) {
        return res;
    }

    *result = QQBYTE(buf);

    if (crc) {
        *crc = CRC_string(*crc, buf, 8);
    }

    return 0;
}

static int skip_data(vfile *vf, size_t size, avuint *crc)
{
    while (size > 0) {
        avbyte buf[1];
        int res = av_read_all(vf, (char*)buf, 1);
        if (res < 0) {
            av_log(AVLOG_ERROR, "URAR: out of data during skipping data");
            return res;
        }
        *crc = CRC_byte(*crc, buf[0]);
        size--;
    }

    return 0;
}

#define READ_VINT(vf, target, crc) {                                    \
        int res = read_vint((vf), (target), (crc));                     \
        if (res < 0) {                                                  \
            return res;                                                 \
        }                                                               \
    }

#define READ_UINT32(vf, target, crc) {                                  \
        int res = read_uint32((vf), (target), (crc));                   \
        if (res < 0) {                                                  \
            return res;                                                 \
        }                                                               \
    }

#define READ_UINT64(vf, target, crc) {                                  \
        int res = read_uint64((vf), (target), (crc));                   \
        if (res < 0) {                                                  \
            return res;                                                 \
        }                                                               \
    }

static void convert_windows_timestamp(avuquad timestamp,
                                      avtimestruc_t *ts)
{
    // windows timestamps are in 100ns from year 1600something
    timestamp *= 100;
    timestamp -= 11644473600000000000ULL;

    ts->sec = timestamp / 1000000000;
    ts->nsec = timestamp % 1000000000;
}

static int parse_rar5_time_header(vfile *vf,
                                  struct rar5_entinfo *ei,
                                  avuint *crc)
{
    // file time
    avuquad flags;
    int is_unix;

    READ_VINT(vf, &flags, crc);

    if (flags & RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_UNIX_TIME) {
        is_unix = 1;
    } else {
        is_unix = 0;
    }

    if (flags & RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_MTIME_PRESENT) {
        if (is_unix) {
            avuint mtime;
            READ_UINT32(vf, &mtime, crc);
            ei->mtime.sec = mtime;
        } else {
            avuquad mtime;
            READ_UINT64(vf, &mtime, crc);
            convert_windows_timestamp(mtime, &ei->mtime);
        }
    }

    if (flags & RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_CTIME_PRESENT) {
        if (is_unix) {
            avuint ctime;
            READ_UINT32(vf, &ctime, crc);
            ei->ctime.sec = ctime;
        } else {
            avuquad ctime;
            READ_UINT64(vf, &ctime, crc);
            convert_windows_timestamp(ctime, &ei->ctime);
        }
    }

    if (flags & RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_ATIME_PRESENT) {
        if (is_unix) {
            avuint atime;
            READ_UINT32(vf, &atime, crc);
            ei->atime.sec = atime;
        } else {
            avuquad atime;
            READ_UINT64(vf, &atime, crc);
            convert_windows_timestamp(atime, &ei->atime);
        }
    }

    if (is_unix && (flags & RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_NSEC_PRECISION)) {
        if (flags & RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_MTIME_PRESENT) {
            avuint t;
            READ_UINT32(vf, &t, crc);
            ei->mtime.nsec = t;
        }
        if (flags & RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_CTIME_PRESENT) {
            avuint t;
            READ_UINT32(vf, &t, crc);
            ei->ctime.nsec = t;
        }
        if (flags & RAR5_HEADER_FILE_HEADER_EXTRA_FILE_TIME_FLAGS_ATIME_PRESENT) {
            avuint t;
            READ_UINT32(vf, &t, crc);
            ei->atime.nsec = t;
        }
    }

    return 0;
}

static int parse_rar5_extra_header(vfile *vf,
                                   avuquad extra_header_bytes,
                                   struct rar5_entinfo *ei,
                                   avuint *crc)
{
    avoff_t start_pos = vf->ptr;

    while (vf->ptr - start_pos < extra_header_bytes) {
        avuquad size;
        avuquad type;
        avoff_t extra_header_pos;
        int res;

        READ_VINT(vf, &size, crc);

        extra_header_pos = vf->ptr;

        READ_VINT(vf, &type, crc);

        if (type == RAR5_HEADER_FILE_HEADER_EXTRA_TYPE_FILE_TIME) {
            res = parse_rar5_time_header(vf, ei, crc);
            if (res < 0) {
                return res;
            }
        }

        if (vf->ptr - extra_header_pos > size ||
            extra_header_pos - start_pos + size > extra_header_bytes) {
            av_log(AVLOG_ERROR, "URAR: invalid extra header");
            return -EINVAL;
        }

        res = skip_data(vf, size - (vf->ptr - extra_header_pos), crc);
        if (res < 0) {
            return res;
        }
    }

    return 0;
}

static int parse_rar5_file_header(vfile *vf, struct archive *arch,
                                  avuquad remaining_header_bytes,
                                  avuint *crc)
{
    avoff_t start_pos = vf->ptr;
    avuquad file_flags;
    avuquad unpacked_size;
    avuquad attributes;
    avuint data_crc = 0;
    avuquad compression_information;
    avuquad host_os;
    avuquad name_length;
    int res;
    char *name = NULL;
    struct rar5_entinfo ei = { NULL, };

    READ_VINT(vf, &file_flags, crc);
    READ_VINT(vf, &unpacked_size, crc );

    if (file_flags & RAR5_HEADER_FILE_HEADER_FILE_FLAGS_UNPACKED_SIZE_UNKNOWN) {
        unpacked_size = 0;
    }

    READ_VINT(vf, &attributes, crc);

    /* uint32? mtime */
    if (file_flags & RAR5_HEADER_FILE_HEADER_FILE_FLAGS_UNIX_TIME_PRESENT) {
        avuint mtime;
        READ_UINT32(vf, &mtime, crc);

        ei.mtime.sec = mtime;
        ei.ctime = ei.mtime;
        ei.atime = ei.mtime;
    }

    /* uint32? data_crc */
    if (file_flags & RAR5_HEADER_FILE_HEADER_FILE_FLAGS_CRC_PRESENT) {
        READ_UINT32(vf, &data_crc, crc);
    }

    READ_VINT(vf, &compression_information, crc);
    READ_VINT(vf, &host_os, crc);
    READ_VINT(vf, &name_length, crc);

    if (name_length <= PATH_MAX) {
        name = av_malloc(name_length + 1);

        res = av_read_all(vf, name, name_length);
        if (res < 0) {
            av_free(name);
            return res;
        }
        name[name_length] = '\0';
        *crc = CRC_string(*crc, (avbyte*)name, name_length);
    }

    res = parse_rar5_extra_header(vf, remaining_header_bytes - (vf->ptr - start_pos), &ei, crc);
    if (res < 0) {
        av_free(name);
        return res;
    }

    if (vf->ptr - start_pos > remaining_header_bytes) {
        av_log(AVLOG_ERROR, "URAR: invalid header");
        av_free(name);
        return -EINVAL;
    }

    res = skip_data(vf, remaining_header_bytes - (vf->ptr - start_pos), crc);
    if (res < 0) {
        av_free(name);
        return res;
    }

    /* convert file attribute */
    if (host_os == RAR5_HEADER_FILE_HEADER_HOST_OS_UNIX) {
        ei.mode = attributes;
    } else {
        // handle windows (host_os==0) and unknown identically
        if (file_flags & RAR5_HEADER_FILE_HEADER_FILE_FLAGS_DIRECTORY_OBJECT) {
            ei.mode = AV_IFDIR | 0700;
        } else {
            ei.mode = AV_IFREG | 0600;
        }
    }

    /* add entry to archive */
    if (name != NULL) {
        ei.name = name;
        ei.linkname = NULL;
        ei.is_dir = file_flags & RAR5_HEADER_FILE_HEADER_FILE_FLAGS_DIRECTORY_OBJECT;
        ei.size = unpacked_size;

        insert_rar5entry(arch, &ei);

        av_free(ei.name);
        av_free(ei.linkname);
    }

    return 0;
}

/**
 * parse a block, return <= 0 for errors, > 0 for block type
 */
static int parse_rar5_block(vfile *vf, struct archive *arch)
{
    int res;
    avuquad header_size;
    avuquad header_type;
    avuquad header_flags;
    avuquad extra_area_size;
    avuquad data_size;
    avuint crc = CRC_START;
    avuint header_crc;
    avoff_t headstart;

    READ_UINT32(vf, &header_crc, NULL);
    READ_VINT(vf, &header_size, &crc);

    /* store current file offset since header flags define visible
       fields, most of them are variable size. To skip all header
       bytes including the unknown, we need to know much bytes we
       already read */
    headstart = vf->ptr;

    READ_VINT(vf, &header_type, &crc);

    if (header_type < RAR5_HEADER_TYPE_MAIN_ARCHIVE_HEADER ||
        header_type > RAR5_HEADER_TYPE_END_OF_ARCHIVE) {
        av_log(AVLOG_ERROR, "URAR: invalid header type");
        return -EINVAL;
    }

    READ_VINT(vf, &header_flags, &crc);

    /* vint? extra_area_size */
    if (header_flags & RAR5_HEADER_FLAGS_EXTRA_PRESENT) {
        READ_VINT(vf, &extra_area_size, &crc);
    } else {
        extra_area_size = 0;
    }

    /* vint? data_size */
    if (header_flags & RAR5_HEADER_FLAGS_DATA_PRESENT) {
        READ_VINT(vf, &data_size, &crc);
    } else {
        data_size = 0;
    }

    /* now we basically have all important fields, parse interesting block or skip the rest */
    if (vf->ptr - headstart > header_size) {
        av_log(AVLOG_ERROR, "URAR: invalid header size");
        return -EINVAL;
    }

    if (header_type == RAR5_HEADER_TYPE_FILE_HEADER) {
        res = parse_rar5_file_header(vf, arch, header_size - (vf->ptr - headstart), &crc);
        if (res < 0) {
            return res;
        }
    } else {
        res = skip_data(vf, header_size - (vf->ptr - headstart), &crc);
        if (res < 0) {
            return res;
        }
    }

    /* check header CRC */
    if (~crc != header_crc) {
        av_log(AVLOG_ERROR, "URAR: invalid crc");
        return -EINVAL;
    }

    /* skip the data area as well, but it is not part of the CRC */
    if (header_flags & RAR5_HEADER_FLAGS_DATA_PRESENT) {
        av_lseek(vf, data_size, AVSEEK_CUR);
    }

    return header_type;
}

static int read_rar5file(vfile *vf, struct archive *arch)
{
    while (1) {
        int res = parse_rar5_block(vf, arch);
        if (res < 0) {
            return res;
        } else if (res == 0) {
            return -EINVAL;
        } else if (res == RAR5_HEADER_TYPE_END_OF_ARCHIVE) {
            break;
        }
    }

    return 0;
}

static int read_rarfile(vfile *vf, struct archive *arch)
{
    avoff_t headstart;
    int res;
    enum rar_format format;

    res = read_marker_block(vf, &format);
    if(res < 0)
        return res;

    if (format == RAR) {
        res = read_archive_header(vf);
        if(res < 0)
            return res;

        headstart = vf->ptr;
        while(1) {
            struct rar_entinfo ei;
    
            res = read_block_header(vf, ei.bh, 0);
            if(res < 0)
                return res;
            if(res == 0)
                break;

            if (bh_type(ei.bh) == B_FILE) {
                ei.name = NULL;
                ei.linkname = NULL;

                res = read_rarentry(vf, &ei);
                if(res < 0) {
                    av_free(ei.name);
                    av_free(ei.linkname);
                    return res;
                }
                ei.datastart = vf->ptr;

                insert_rarentry(arch, &ei);
                av_free(ei.name);
                av_free(ei.linkname);
            }
            av_lseek(vf, headstart + bh_size(ei.bh), AVSEEK_SET);
            headstart = vf->ptr;
        }
    } else if (format == RAR50) {
        return read_rar5file(vf, arch);
    }

    return 0;
}

static int parse_rarfile(void *data, ventry *ve, struct archive *arch)
{
    int res;
    vfile *vf;

    res = av_open(ve->mnt->base, AVO_RDONLY, 0, &vf);
    if(res < 0)
        return res;

    res = read_rarfile(vf, arch);

    av_close(vf);
    
    return res;  
}

/* FIXME: Because we use the 'rar' program to extract the contents of
   each file individually , we get _VERY_ poor performance */

static int get_rar_file(ventry *ve, struct archfile *fil, int fd)
{
    int res;
    struct rarnode *info = (struct rarnode *) fil->nod->data;
    struct realfile *rf;
    const char *prog[7];
    struct proginfo pri;
    static int rar_available = 1;

    res = av_get_realfile(ve->mnt->base, &rf);
    if(res < 0)
        return res;

    /* prepare arguments */
    prog[0] = "rar";
    prog[1] = "p";
    prog[2] = "-c-";
    prog[3] = "-ierr";
    prog[4] = rf->name;
    prog[5] = info->path;
    prog[6] = NULL;
 
    if(rar_available) {
        av_init_proginfo(&pri);
        pri.prog = prog;
        pri.ifd = open("/dev/null", O_RDWR);
        pri.ofd = fd;
        pri.efd = pri.ifd;
        
        res = av_start_prog(&pri);
        close(pri.ifd);
        
        if(res == 0)
            res = av_wait_prog(&pri, 0, 0);
    } else {
        /* force unrar execution */
        res = -EIO;
    }
    
    if(res == -EIO)
    {
        /* rar failed or unavailable, try unrar */
        rar_available = 0;
        
        prog[0] = "unrar";
        av_init_proginfo(&pri);
        pri.prog = prog;
        pri.ifd = open("/dev/null", O_RDWR);
        pri.ofd = fd;
        pri.efd = pri.ifd;
        
        res = av_start_prog(&pri);
        close(pri.ifd);
        
        if(res == 0)
            res = av_wait_prog(&pri, 0, 0);

        if(res == -EIO) {
            /* unrar failed too so reset rar_available */
            rar_available = 1;
        }
    }

    av_unref_obj(rf);

    return res;
}

static int do_unrar(ventry *ve, struct archfile *fil)
{
    int res;
    struct rarfile *rfil;
    char *tmpfile;
    int fd;

    res = av_get_tmpfile(&tmpfile);
    if(res < 0)
        return res;

    fd = open(tmpfile, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if(fd == -1) {
        res = -errno; 
        av_log(AVLOG_ERROR, "RAR: Could not open %s: %s", tmpfile,
               strerror(errno));
        av_del_tmpfile(tmpfile);
        return res;
    }

    res = get_rar_file(ve, fil, fd);
    if(res < 0) {
        close(fd);
        av_del_tmpfile(tmpfile);
        return res;
    }

    AV_NEW(rfil);
    rfil->tmpfile = tmpfile;
    rfil->fd = fd;

    fil->data = rfil;

    return 0;
}


static int rar_open(ventry *ve, struct archfile *fil)
{
    struct rarnode *info = (struct rarnode *) fil->nod->data;

    if(info == NULL) {
        /* access to base rar directory */
        return -EISDIR;
    }
    
    if(info->flags & FF_WITH_PASSWORD) {
        av_log(AVLOG_WARNING, "URAR: File password protected, sorry...");
        return -EACCES;
    }

    if(info->method != M_STORE)
        return do_unrar(ve, fil);
    
    return 0;
}

static int rar_close(struct archfile *fil)
{
    struct rarfile *rfil = (struct rarfile *) fil->data;

    if(rfil != NULL) {
        close(rfil->fd);
        av_del_tmpfile(rfil->tmpfile);
        av_free(rfil);
    }
    
    return 0;
}

static avssize_t rar_read(vfile *vf, char *buf, avsize_t nbyte)
{
    avssize_t res;
    struct archfile *fil = arch_vfile_file(vf);
    struct rarfile *rfil = (struct rarfile *) fil->data;

    if(rfil == NULL)
        return av_arch_read(vf, buf, nbyte);

    if(lseek(rfil->fd, vf->ptr, SEEK_SET) == -1)
        return -errno;

    res = read(rfil->fd, buf, nbyte);
    if(res == -1)
        return -errno;

    vf->ptr += res;

    return res;
}

extern int av_init_module_urar(struct vmodule *module);

int av_init_module_urar(struct vmodule *module)
{
    int res;
    struct avfs *avfs;
    struct ext_info rarexts[3];
    struct archparams *ap;

    rarexts[0].from = ".rar",  rarexts[0].to = NULL;
    rarexts[1].from = ".sfx",  rarexts[1].to = NULL;
    rarexts[2].from = NULL;

    res = av_archive_init("urar", rarexts, AV_VER, module, &avfs);
    if(res < 0)
        return res;
    
    ap = (struct archparams *) avfs->data;
    ap->parse = parse_rarfile;
    ap->open = rar_open;
    ap->close = rar_close;
    ap->read = rar_read;

    initCRC();

    av_add_avfs(avfs);

    return 0;
}
