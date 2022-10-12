#include <stdio.h>

char name[32];

int main()
{
	printf("Enter a name: ");
	fflush(stdout);
	read(0, name, 32);
	printf("Obi Wan says: Hello there %s", name);

	printf("The time is currently: ");
	fflush(stdout);
	system("/bin/date");

	char echo[100];
	printf("Phrase to echo: ");
	fflush(stdout);
	read(0, echo, 1000);
	puts(echo);

	return 0;
}