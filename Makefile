all: build/ip_whitelist build/basic_maps

build/ip_whitelist: build ip_whitelist/ip_whitelist.c
	gcc -o build/ip_whitelist ip_whitelist/ip_whitelist.c

build/basic_maps: build basic_maps/basic_maps.c
	gcc -o build/basic_maps basic_maps/basic_maps.c

build:
	mkdir build

clean:
	rm -r build