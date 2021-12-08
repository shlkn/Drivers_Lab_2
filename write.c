#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lab2.h"


int main()
{
	int file = open("/dev/lab2", O_WRONLY);
	char *temp = "Hello from userspace";
	printf("%s\n", temp);
	//ioctl(file, CH_BUF_SIZE, 10);
	int writen_bytes_cnt = write(file, temp, 20);
	printf("count of writen bytes %d\n", writen_bytes_cnt);
	close(file);
	return 0;
}