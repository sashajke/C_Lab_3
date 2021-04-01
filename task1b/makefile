all : linkedList

linkedList : linkedList.c
	gcc -g -m32 -c -o linkedList.o linkedList.c
	gcc -g -m32 linkedList.o -o linkedList

clean :
	rm linkedList.o
