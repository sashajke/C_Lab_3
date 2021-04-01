#include <stdio.h>
#include <stdlib.h>


// helper function

void printHex(char * buffer, int length)
{
  int i;
  for(i = 0; i < length; i++)
  {
    printf("%02X ",*(buffer+i) & 0xFF);
  }
}

int main(int argc, char **argv) {
  FILE* input;
  char buffer[1];
  if(argc > 1)
  {
    input = fopen(argv[1],"r");
    while(fread(&buffer,sizeof(char),1,input) == 1)
    {
      printHex(buffer,1);
    }
    printf("\n");
    fclose(input);
  }
  return 0;
}
