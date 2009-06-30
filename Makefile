CC		= gcc
TARGETS		?= netcfg-static netcfg

LDOPTS		= -ldebconfclient -ldebian-installer
CFLAGS		= -W -Wall -DNDEBUG 
COMMON_OBJS	= netcfg-common.o wireless.o

ifneq ($(DEB_HOST_ARCH_OS),linux)
NO_WIRELESS	= 1
endif

ifeq ($(NO_WIRELESS),)
LDOPTS		+= -liw
CFLAGS		+= -DWIRELESS
endif

ifneq (,$(findstring noopt,$(DEB_BUILD_OPTIONS)))
CFLAGS += -O0 -g3
else
CFLAGS += -Os -fomit-frame-pointer
endif

all: $(TARGETS)

netcfg-static: netcfg-static.o static.o
ifeq ($(DEB_HOST_ARCH_OS),linux)
netcfg: netcfg.o dhcp.o static.o ethtool-lite.o
else
netcfg: netcfg.o dhcp.o static.o
endif

$(TARGETS): $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDOPTS)

%.o: %.c
	$(CC) -c $(CFLAGS) $(DEFS) $(INCS) -o $@ $<

clean:
	rm -f $(TARGETS) *.o

.PHONY: all clean

# vim:ts=8:noet
