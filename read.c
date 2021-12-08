#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


int main()
{
	int file = open("/dev/lab2", O_RDONLY);
	char temp[200];
	int read_cnt = read(file, temp, 20);
	printf("count of readen bytes %d\n", read_cnt);
	printf("%s\n", temp);
	close(file);
	return 0;
}