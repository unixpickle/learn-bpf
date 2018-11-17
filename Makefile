all: build/ip_whitelist build/basic_maps build/key_logger

build/ip_whitelist: build ip_whitelist/ip_whitelist.c
	gcc -o build/ip_whitelist ip_whitelist/ip_whitelist.c

build/basic_maps: build basic_maps/basic_maps.c
	gcc -o build/basic_maps basic_maps/basic_maps.c

build/key_logger: build key_logger/key_logger.c
	gcc -o build/key_logger key_logger/key_logger.c

build:
	mkdir build

clean:
	rm -r build