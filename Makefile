CFLAGS=-Icommon

all: build build/ip_whitelist build/basic_maps build/key_logger build/tld_count

build/ip_whitelist: ip_whitelist/ip_whitelist.c
	$(CC) $(CFLAGS) -o $@ $^

build/basic_maps: basic_maps/basic_maps.c
	$(CC) $(CFLAGS) -o $@ $^

build/key_logger: key_logger/key_logger.c common/kprobes.c
	$(CC) $(CFLAGS) -o $@ $^

build/tld_count: tld_count/tld_count.c
	$(CC) $(CFLAGS) -o $@ $^

build:
	mkdir build

clean:
	rm -r build