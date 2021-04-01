all : hexaPrint

hexaPrint : hexaPrint.c
	gcc -g -m32 -c -o hexaPrint.o hexaPrint.c
	gcc -g -m32 hexaPrint.o -o hexaPrint

clean :
	rm hexaPrint.o
