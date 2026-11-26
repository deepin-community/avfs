/* this is a very simple test tool for reading any file in an archive, just give the name as argument.
 * This tool is not meant to be correct or a good example, it is pretty much only useful for debugging
 * avfs.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <virtual.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

struct arg {
    char *in;
    char *out;
    size_t steps;
};

static void *f( void *_arg )
{
    struct arg *a= _arg;
    int fd;
    ssize_t len;
    char buf[128*1024];

    struct stat stat_buf;

    if ( virt_stat( a->in, &stat_buf ) != 0 ) {
        printf( "Could not stat %s (%s)\n", a->in, strerror( errno ) );
    } else {
        printf( "Size: %lu\n", stat_buf.st_size );
    }
  
    fd = virt_open( a->in, O_RDONLY, 0 );
    if ( fd >= 0 ) {
        ssize_t total_len = 0;

        for (;;) {
            len = virt_read( fd, buf, sizeof( buf ) );
            total_len += len;

            printf( "Bytes read: %lu\n", len );

            if ( len == 0 ) break;
            else if ( len < 0 ) {
                printf( "Error: %s\n", strerror( errno ) );
                break;
            }
        }

        printf( "Total len:%lu\n", total_len );

        // now seek backwards and write output to second file
        size_t seek_steps = a->steps;
        if ( seek_steps > sizeof( buf ) ) {
            seek_steps = sizeof( buf );
            printf( "Limit seeking to %lu stepping\n", seek_steps );
        }

        int outfd = virt_open( a->out, O_CREAT | O_WRONLY, 0600 );
        if ( outfd >= 0 ) {
            for (;;) {
                size_t readlen = seek_steps;
                if ( total_len < readlen) {
                    readlen = total_len;
                    total_len = 0;
                } else {
                    total_len -= readlen;
                }
                
                virt_lseek( fd, total_len, 0 );
                len = virt_read( fd, buf, readlen );

                //printf( "Bytes read by seeking to %lu: %lu\n", total_len, len );

                virt_lseek( outfd, total_len, 0 );
                virt_write( outfd, buf, len );

                if ( total_len == 0 ) break;
            }
            virt_close( outfd );
        } else {
            printf("can't open output file '%s'\n", a->out );
        }

        virt_close( fd );
    } else {
        printf( "Could not open %s (%s)\n", a->out, strerror( errno ) );
    }
    return 0;
}

int main( int argc, char **argv )
{
    if ( argc < 5 ) {
        return 0;
    }

    struct arg a1, a2;

    a1.in = argv[1];
    a2.in = a1.in;

    a1.steps = atoi( argv[2] );
    a2.steps = a1.steps;

    a1.out = argv[3];
    a2.out = argv[4];

    pthread_t id1, id2;

    pthread_create( &id1, NULL, f, &a1 );
    pthread_create( &id2, NULL, f, &a2 );

    pthread_join( id1, NULL );
    pthread_join( id2, NULL );

    return 0;
}
