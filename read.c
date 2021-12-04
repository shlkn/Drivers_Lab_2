#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


int main()
{
	int file = open("/dev/lab2", O_RDONLY);
	char temp[8860];
	int read_cnt = read(file, temp, 8860);
	printf("count of readen bytes %d\n", read_cnt);
	printf("%s\n", temp);
	//for(i = 0; i < 200; i++)
		//printk("%X", temp[i]);
	close(file);
	return 0;
}