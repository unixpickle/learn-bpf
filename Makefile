all: build build/ip_whitelist build/basic_maps build/key_logger build/tld_count

build/ip_whitelist: ip_whitelist/ip_whitelist.c
	gcc -o $@ $^

build/basic_maps: basic_maps/basic_maps.c
	gcc -o $@ $^

build/key_logger: key_logger/key_logger.c
	gcc -o $@ $^

build/tld_count: tld_count/tld_count.c
	gcc -o $@ $^

build:
	mkdir build

clean:
	rm -r build