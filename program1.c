#include <stdio.h>

int main()
{
	FILE *f = fopen("/dev/lab2", "rw");
	char *temp = "Hello from userspace";
	printf("%s\n", temp);
	fputs(temp, f);
	fclose(f);
	return 0;
}