all: build/ip_whitelist

build/ip_whitelist: build ip_whitelist/ip_whitelist.c
	gcc -o build/ip_whitelist ip_whitelist/ip_whitelist.c

build:
	mkdir build

clean:
	rm -r build