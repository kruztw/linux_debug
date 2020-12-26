#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

#define BUFSIZE 4096

int main()
{
    int         fd, ret;
    char            buf[BUFSIZE];
    char b[] = "fuck";
    unsigned long int   a = 0x6161616161616161;

    printf( "a=0x%016lX addr: %p \n", a, &a ); // must print to allocate page table
    if ( (fd = open( "/proc/registers", O_RDONLY ) ) < 0 )
    {
        fprintf( stderr, "Open /proc/registers file failed! \n" );
        exit( EXIT_FAILURE );
    }

    if ( (ret = read( fd, buf, sizeof buf - 1 ) ) < 0 )
    {
        perror( "/proc/registers" );
        exit( EXIT_FAILURE );
    }

    buf[ret] = 0;
    close( fd );
    puts( buf );

    if ( ( fd = open("/proc/ptdump", O_RDONLY) ) < 0 )
    {
	    fprintf(stderr, "Open /proc/ptdump file failed!\n");
	    exit(-1);
    }

    ioctl(fd, 0, &a);
    

    while ( 1 );
    return(0);
}
