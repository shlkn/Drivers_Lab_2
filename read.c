#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


int main()
{
	int file = open("/dev/lab2", O_RDWR);
	char temp[200];
	read(file, temp, 20);
	printf("%s\n", temp);
	close(file);
	return 0;
}