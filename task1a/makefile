all : virusDetector

virusDetector : virusDetector.c
	gcc -g -m32 -c -o virusDetector.o virusDetector.c
	gcc -g -m32 virusDetector.o -o virusDetector

clean :
	rm virusDetector.o
