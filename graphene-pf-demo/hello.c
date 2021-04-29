#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(void){
	printf("hello!\n");

	//fopen
	FILE *fpwrite = fopen("data/secret.txt", "w");
	if(fpwrite == NULL) {
		return -1;
	}
	//fwrite
	char a[] = "Time is fast";
	fwrite( a, sizeof(a), 1, fpwrite);
	//fprintf
	// for (int i = 0; i < 10; i++) {
	// 	fprintf(fpwrite, "%d ", i);
	// }
	//fclose
	fclose(fpwrite);

	FILE *fpread = fopen("data/secret.txt", "r");
	if(fpread == NULL) {
		printf("secret.txt not found\n");
		return -2;
	}
	//fseek
	fseek(fpread, 0, SEEK_SET);
	//fread
	char b[50];
	fread(b, sizeof(a), 1, fpread);
	fclose(fpread);

	printf("b[] = %s\n", b);
	
	return 0;
}
