#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include "lab2.h"


int main()
{
	int file = open("/dev/lab2", O_RDONLY);
	int cnt = ioctl(file, GET_WRITE_CNT, 777);
	char *temp = malloc(sizeof(char) * cnt);
	int read_cnt = read(file, temp, cnt);
	printf("count of readen bytes %d\n", read_cnt);
	printf("%s\n", temp);
	close(file);
	return 0;
}