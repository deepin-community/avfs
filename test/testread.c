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

int main( int argc, char **argv )
{
    int fd;
    ssize_t len;
    char buf[128*1024];

    if ( argc < 2 ) {
        return 0;
    }

    struct stat stat_buf;

    if ( virt_stat( argv[1], &stat_buf ) != 0 ) {
        printf( "Could not stat %s\n", argv[1] );
    } else {
        printf( "Size: %lu\n", stat_buf.st_size );
    }
  
    fd = virt_open( argv[1], O_RDONLY, 0 );
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

        if ( total_len >= sizeof( buf ) ) {
            for (;;) {
                total_len -= sizeof( buf );
                
                virt_lseek( fd, total_len, 0 );
                len = virt_read( fd, buf, sizeof( buf ) );

                printf( "Bytes read by seeking to %lu: %lu\n", total_len, len );

                if ( total_len < sizeof( buf ) ) break;
            }
        }

        virt_close( fd );
    }
    return 0;
}
