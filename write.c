#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


int main()
{
	int file = open("/dev/lab2", O_RDWR);
	char *temp = "Hello from userspace";
	for(int i = 0; i < 20; i++)
		printf("%X\n", temp[i]);
	printf("%s\n", temp);
	write(file, temp, 20);
	close(file);
	return 0;
}