#include <stdio.h>
#include <stdlib.h>


typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
} virus;


virus* readVirus(FILE* input)
{
  unsigned short virusSize = 0;
  virus* toReturn = (virus*)malloc(sizeof(virus));
  if(toReturn == NULL)
  {
    // error handling
  }
  if(fread(toReturn,1,18,input) != 18)
  {
    free(toReturn);
    return NULL;
  }
  virusSize = toReturn -> SigSize;
  toReturn -> sig = calloc(virusSize,sizeof(unsigned char));
  if(fread(toReturn -> sig,1,virusSize,input) != virusSize)
  {
    // error when reading
  }
  return toReturn;
}

void virusDestructor(virus* vir)
{
  if(vir != NULL)
  {
    free(vir -> sig);
  }
}

void printVirusName(char name[],FILE* output)
{
  const int sizeOfArray = 16;
  int i;
  fprintf(output, "Virus name: ");
  for(i = 0; i < sizeOfArray; i++)
  {
    if(name[i] != '\0')
    {
      fprintf(output,"%c",name[i]);
    }
  }
  fprintf(output,"\n");

}

void printVirusSig(unsigned char * sig,unsigned short length,FILE* output)
{
  int i;
  fprintf(output, "signature:\n");

  for(i = 0; i < length; i++)
  {
    if(i < length-1) // remove the last space
      fprintf(output, "%02X ", *(sig+i));
    else
      fprintf(output, "%02X", *(sig+i));

  }
  fprintf(output, "\n\n");
}
void printVirus(virus* virusToPrint,FILE* output)
{
  printVirusName(virusToPrint -> virusName,output);
  fprintf(output, "Virus size: %d\n", virusToPrint -> SigSize);
  printVirusSig(virusToPrint -> sig,virusToPrint -> SigSize,output);
}

int main(int argc, char const *argv[]) {
  char header[4];
  FILE* virusInfo = fopen("signatures-L","r");
  virus* nextVirus;

  if(fread(&header,1,4,virusInfo) != 4)
  {
    // error handling
  }

  while((nextVirus = readVirus(virusInfo)) != NULL)
  {
    printVirus(nextVirus,stdout);
    virusDestructor(nextVirus);
    free(nextVirus);
  }
  fclose(virusInfo);

  return 0;
}
