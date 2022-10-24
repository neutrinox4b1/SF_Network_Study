#include<stdio.h>
#include<fcntl.h>
#include<unistd.h>
#include<stdlib.h>

int main()
{
    int fd;
    __uint32_t test;

    fd = open("/dev/urandom", O_RDONLY);
    
    if(fd == -1)
    {
        perror("open error");
        exit(1);
    }

    read(fd, &test, 4);
    
    printf("0x%04x\n",test);

    return 0;
}