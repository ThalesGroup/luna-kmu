# Linux CLI build for luna-kmu.
# Requires Luna Client SDK headers (default /usr/safenet/lunaclient).

LUNA_CLIENT ?= /usr/safenet/lunaclient
PREFIX ?= /usr/local
OUTDIR ?= linux-build
TARGET = $(OUTDIR)/kmu

CC ?= gcc
CFLAGS ?= -g -O0 -Wall -Wno-unused-variable -Wno-unused-but-set-variable \
	-Wno-unknown-pragmas -Wno-pointer-sign -fcommon
CPPFLAGS += -DOS_UNIX -D_GNU_SOURCE \
	-I./kmu/inc -I./pkcs11/inc -I./ressource -I./util/inc \
	-I$(LUNA_CLIENT)/sdk/include \
	-I$(LUNA_CLIENT)/sdk/external \
	-I$(LUNA_CLIENT)/sdk/external/RSA
LDFLAGS += -ldl

SRCS = \
	kmu/src/cmd.c \
	kmu/src/cmdarg.c \
	kmu/src/kmu.c \
	kmu/src/parser.c \
	pkcs11/src/p11.c \
	pkcs11/src/p11util.c \
	util/src/asn1.c \
	util/src/base64.c \
	util/src/console.c \
	util/src/file.c \
	util/src/pkcs8.c \
	util/src/str.c \
	util/src/tmd.c \
	util/src/tr31.c

.PHONY: all clean

all: $(TARGET)

$(OUTDIR):
	mkdir -p $(OUTDIR)

$(TARGET): $(SRCS) | $(OUTDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(SRCS) $(LDFLAGS) -o $@
	strip $@

clean:
	rm -f $(TARGET)
