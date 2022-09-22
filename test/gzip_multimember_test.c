#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <virtual.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main( int argc, char **argv )
{
    int fd;
    ssize_t len;
    char buf[128*1024];

    struct stat stat_buf;
    const char *testfile = "numchar.gz#";

    if ( virt_stat( testfile, &stat_buf ) != 0 ) {
        printf("FAILED: stat failed\n");
        return EXIT_FAILURE;
    }

    if ( stat_buf.st_size != 2 * 1048576 ) {
        printf("FAILED: invalid size\n");
        return EXIT_FAILURE;
    }
  
    fd = virt_open( testfile, O_RDONLY, 0 );
    if ( fd < 0 ) {
        printf("FAILED: open failed\n");
        return EXIT_FAILURE;
    }

    ssize_t total_len;

    for (;;) {
        len = virt_read( fd, buf, sizeof( buf ) );
        total_len += len;

        if ( len == 0 ) break;
        else if ( len < 0 ) {
            printf("FAILED: read failed\n");
            return EXIT_FAILURE;
        }
    }

    if ( total_len != 2 * 1048576 ) {
        printf("FAILED: invalid size\n");
        return EXIT_FAILURE;
    }

    for (;;) {
        total_len -= sizeof( buf );
                
        virt_lseek( fd, total_len, 0 );
        len = virt_read( fd, buf, sizeof( buf ) );

        if ( total_len >= 1048576 ) {
            char ch = 'A' + ( total_len - 1048576 ) % 10;

            if ( buf[0] != ch ) {
                printf("FAILED: invalid char:%c at %lu\n", ch, total_len);
                return EXIT_FAILURE;
            }
        } else {
            char ch = '0' + ( total_len ) % 10;

            if ( buf[0] != ch ) {
                printf("FAILED: invalid char:%c at %lu\n", ch, total_len);
                return EXIT_FAILURE;
            }
        }

        if ( total_len < sizeof( buf ) ) break;
    }

    virt_close( fd );

    printf("OK\n");

    return 0;
}
