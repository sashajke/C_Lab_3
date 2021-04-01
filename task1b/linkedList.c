#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
} virus;


typedef struct link link;

struct link {
    link *nextVirus;
    virus *vir;
};

struct fun_desc {
  char *name;
  link* (*fun)(link* viruses);
};


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
    else
    {
      break;
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




/* Print the data of every link in list to the given stream. Each item followed by a newline character. */
void list_print(link *virus_list, FILE* output)
{
  while(virus_list != NULL)
  {
    printVirus(virus_list -> vir,output);
    virus_list = virus_list -> nextVirus;
  }
  // if(virus_list != NULL)
  // {
  //   printVirus(virus_list -> vir,output);
  //   //list_print(virus_list -> nextVirus,output);
  // }
}

link* addToBeggining(link* virus_list,virus* data)
{
  link* temp = malloc(sizeof(link));
  temp -> vir = data;
  temp -> nextVirus = virus_list;
  return temp;
}

void addToEnd(link* virus_list,virus* data)
{

  if(virus_list -> nextVirus == NULL)
  {
    link* temp = malloc(sizeof(link));
    temp -> nextVirus = NULL;
    temp -> vir = data;
    virus_list -> nextVirus = temp;
  }
  else
    addToEnd(virus_list -> nextVirus,data);
}
/* Add a new link with the given data to the list
   (either at the end or the beginning, depending on what your TA tells you),
   and return a pointer to the list (i.e., the first link in the list).
   If the list is null - create a new entry and return a pointer to the entry. */
link* list_append(link* virus_list, virus* data)
{
  if(virus_list == NULL)
  {
    virus_list = (link*)malloc(sizeof(link));
    virus_list -> nextVirus = NULL;
    virus_list -> vir = data;
  }
  else
  {
    addToEnd(virus_list,data);
    // or to beggining , depends on the TA
  }
  return virus_list;
}


void virusDestructor(virus* vir)
{
  if(vir != NULL)
  {
    free(vir -> sig);
  }
}

/* Free the memory allocated by the list. */
void list_free(link *virus_list)
{
  if(virus_list != NULL)
  {
    virusDestructor(virus_list -> vir);
    free(virus_list -> vir);
    list_free(virus_list -> nextVirus);
    free(virus_list);
  }
}



link* loadSignatures(link* viruses)
{
  const int fileNameSize = 255;
  char header[4];
  virus* nextVirus;
  FILE* virusFile;
  char fileName[fileNameSize];

  if(viruses != NULL)
    list_free(viruses);
  printf("please enter the signature file name\n");
  if(fgets(fileName,fileNameSize,stdin) != NULL)
  {
    fileName[strcspn(fileName,"\r\n")] = 0;
    virusFile = fopen(fileName,"r");
    if(virusFile == NULL)
    {
      exit(0);
    }
    // read the VISL
    if(fread(&header,1,4,virusFile) != 4)
    {
      fclose(virusFile);
      exit(0);
      // error handling
    }
    while((nextVirus = readVirus(virusFile)) != NULL)
    {
      viruses = list_append(viruses,nextVirus);
    }
    fclose(virusFile);
  }
  return viruses;
}
link* printSignatures(link* viruses)
{
  if(viruses != NULL)
  {
    list_print(viruses,stdout);
  }
  return viruses;
}

void executeMenu(struct fun_desc* menu)
{
  link* viruses = NULL;
  const int bufferSize = 255;
  int i,selection,bound = 2;
  char inputFromUser[bufferSize];

  while (1) {
    printf("Please choose a function:\n");
    for(i = 0;i < bound; i++)
    {
      printf("%d) %s\n",i+1,(menu+i) -> name);
    }
    printf("Option: ");
    if(fgets(inputFromUser,bufferSize,stdin)!= NULL)
    {
      sscanf(inputFromUser,"%d",&selection);
      printf("\n");
      if(selection < 0 || selection > bound)
      {
        printf("Not Within Bounds\n");
        list_free(viruses);
        exit(0);
      }
      printf("Within Bounds\n");
      viruses = (menu+selection-1) -> fun(viruses);
      printf("DONE.\n");
    }
  }
}
int main(int argc, char const *argv[]) {
  struct fun_desc menu[] = {{"Load Signatures",loadSignatures},{"Print Signatures",printSignatures},{NULL,NULL}};
  executeMenu(menu);
  return 0;
}
