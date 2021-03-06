CFLAGS=-Icommon

all: build build/ip_whitelist build/basic_maps build/key_logger build/tld_count build/user_track build/probe_count build/connect_log

build/ip_whitelist: ip_whitelist/ip_whitelist.c
	$(CC) $(CFLAGS) -o $@ $^

build/basic_maps: basic_maps/basic_maps.c
	$(CC) $(CFLAGS) -o $@ $^

build/key_logger: key_logger/key_logger.c common/kprobes.c common/ring_queue.c
	$(CC) $(CFLAGS) -o $@ $^

build/tld_count: tld_count/tld_count.c
	$(CC) $(CFLAGS) -o $@ $^

build/user_track: user_track/user_track.c common/kprobes.c
	$(CC) $(CFLAGS) -o $@ $^

build/probe_count: probe_count/probe_count.c common/kprobes.c
	$(CC) $(CFLAGS) -o $@ $^

build/connect_log: connect_log/connect_log.c common/kprobes.c common/ring_queue.c
	$(CC) $(CFLAGS) -o $@ $^

build:
	mkdir build

clean:
	rm -r build