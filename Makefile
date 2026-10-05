CC      ?= cc
CFLAGS  ?= -O2 -g -D_FORTIFY_SOURCE=2
LDLIBS  ?=
PREFIX  ?= /usr
DESTDIR ?=
VERSION := $(shell sed -n 's/^\#define MINIVPN_VERSION "\(.*\)"/\1/p' src/minivpn.h)

# Flags the build needs regardless of what CFLAGS is overridden with.
REQUIRED_CFLAGS := -std=c11 -D_GNU_SOURCE -Isrc -MMD -MP \
                   -Wall -Wextra -Wshadow -Wformat=2 -Wno-unused-parameter \
                   -fstack-protector-strong

CORE_OBJ := src/crypto.o src/proto.o src/channel.o src/replay.o src/util.o src/log.o \
            src/config.o src/license.o src/devices.o
APP_OBJ  := src/main.o src/server.o src/client.o src/tun.o src/sys.o src/control.o

all: minivpn

%.o: %.c
	$(CC) $(REQUIRED_CFLAGS) $(CFLAGS) -c -o $@ $<

minivpn: $(APP_OBJ) $(CORE_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) -lcrypto

tests/unit_tests: tests/unit_tests.o $(CORE_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) -lcrypto

# Vendor-only: issues license files. Never shipped.
tools/license-tool: tools/license-tool.o $(CORE_OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS) -lcrypto

# Creates a new license-signing key pair and embeds the public half.
# WARNING: licenses signed with the previous key stop validating.
vendor-key: tools/license-tool
	./tools/license-tool keygen $(if $(FORCE),--force)
	$(MAKE) minivpn

test: tests/unit_tests
	./tests/unit_tests
	python3 -m unittest discover -s tests -p 'test_admin.py' -q

# Needs root: builds network namespaces and runs real tunnels between them.
integration: minivpn tools/license-tool
	./tests/integration.sh

# Debug build with AddressSanitizer + UndefinedBehaviorSanitizer.
sanitize: clean
	$(MAKE) CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="-fsanitize=address,undefined" minivpn tests/unit_tests tools/license-tool

install: minivpn
	install -D -m 0755 minivpn $(DESTDIR)$(PREFIX)/sbin/minivpn
	install -D -m 0755 admin/minivpn-admin $(DESTDIR)$(PREFIX)/sbin/minivpn-admin
	install -D -m 0644 packaging/minivpn-server.service $(DESTDIR)/lib/systemd/system/minivpn-server.service
	install -D -m 0644 packaging/minivpn-client@.service $(DESTDIR)/lib/systemd/system/minivpn-client@.service
	install -D -m 0644 packaging/minivpn-admin.service $(DESTDIR)/lib/systemd/system/minivpn-admin.service
	install -D -m 0644 packaging/server.conf $(DESTDIR)$(PREFIX)/share/minivpn/server.conf.example

deb: minivpn
	./packaging/build-deb.sh $(VERSION)

clean:
	rm -f minivpn tests/unit_tests tools/license-tool src/*.o src/*.d tests/*.o tests/*.d tools/*.o tools/*.d
	rm -rf build

.PHONY: all test integration sanitize vendor-key install deb clean

-include $(wildcard src/*.d tests/*.d tools/*.d)
