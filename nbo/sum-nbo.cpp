#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

uint32_t parser(const char* file){
	FILE* fp = fopen(file, "rb");
	if (fp==NULL)
		printf("Error");

	uint32_t n;
	size_t read_len = fread(&n, 1, sizeof(uint32_t),fp);

	fclose(fp);
	return ntohl(n);
}

int main(int argc, char* argv[]){
	if (argc < 2)
		printf("Argument Error");
	
	uint32_t sum = 0;
	for (int i=1; i<argc;i++){
		uint32_t val  = parser(argv[i]);
		sum += val;
		printf("%u(0x%08x)",val,val);
		if (i<argc-1)
			printf("+");
	}


	printf(" = %u(0x%08x)\n", sum, sum);
	return 0;
}
