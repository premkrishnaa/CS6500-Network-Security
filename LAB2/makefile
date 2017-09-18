all: lab2

lab2: lab2.c
	gcc -w -o lab2 lab2.c -L/usr/local/lib -lssl -lcrypto

clean:
	rm lab2 alt.txt out100KB.bin

remove:
	rm *_pub.txt *_priv.txt