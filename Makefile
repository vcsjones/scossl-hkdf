all: main

main.o: main.c
	clang -c main.c -Wall -o main.o

main: main.o
	clang -o main -lssl -lcrypto main.o

clean:
	rm main.o main