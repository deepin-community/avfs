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
    if ( argc < 2 ) {
        return 0;
    }

    DIR *d = virt_opendir( argv[1] );
    if ( d ) {
        struct dirent *de;

        while ( ( de = virt_readdir( d ) ) ) {
            printf( "Dir entry: %s\n", de->d_name );
        }

        virt_closedir( d );
    } else {
        printf( "Could not open dir %s (%s)\n", argv[1], strerror( errno ) );
    }
    return 0;
}
