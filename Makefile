CXX ?= g++
CPPFLAGS += -I./src
CXXFLAGS ?= -Wall -Wextra -Os -ffunction-sections -fdata-sections
LDFLAGS += -Wl,--gc-sections
GINIT_LDLIBS += -lcrypt
NETCFG_LDLIBS += -lssl -lcrypto -lz -lzstd -ldl -lpthread
LOGIN_LDLIBS += -lpam -lpam_misc
TARGET_RUNTIME_LD :=

TARGET_CXX_VERSION := $(shell find $(ROOTFS)/usr/include/c++ -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | grep -E '^[0-9]+$$' | sort -V | tail -n1)
ifneq ($(strip $(TARGET_CXX_VERSION)),)
CPPFLAGS += -nostdinc++
CPPFLAGS += -isystem $(ROOTFS)/usr/include/c++/$(TARGET_CXX_VERSION)
CPPFLAGS += -isystem $(ROOTFS)/usr/include/x86_64-linux-gnu/c++/$(TARGET_CXX_VERSION)
CPPFLAGS += -isystem $(ROOTFS)/usr/include/c++/$(TARGET_CXX_VERSION)/backward
TARGET_RUNTIME_LD += $(ROOTFS)/lib64/ld-linux-x86-64.so.2
endif

SRCDIR = src
OBJDIR = obj
BINDIR = bin
LIBDIR = lib

# Targets 
TARGETS = $(BINDIR)/ginit $(BINDIR)/ginit-netcfg $(BINDIR)/getty $(BINDIR)/login
LIBRARY = $(LIBDIR)/libgemcore.a

# Objects
LIB_OBJS = $(OBJDIR)/signals.o $(OBJDIR)/network.o $(OBJDIR)/user_mgmt.o $(OBJDIR)/user_mgmt_bootstrap.o
GINIT_OBJS = $(OBJDIR)/ginit.o $(OBJDIR)/gservice_parser.o $(OBJDIR)/gservice_manager.o
NETCFG_OBJS = $(OBJDIR)/ginit_netcfg.o
GETTY_OBJS = $(OBJDIR)/getty.o
LOGIN_OBJS = $(OBJDIR)/login.o

all: $(BINDIR) $(OBJDIR) $(LIBDIR) $(LIBRARY) $(TARGETS)

$(BINDIR) $(OBJDIR) $(LIBDIR):
	mkdir -p $@

$(LIBRARY): $(LIB_OBJS)
	ar rcs $@ $^

$(BINDIR)/ginit: $(GINIT_OBJS) $(LIBRARY)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $(GINIT_OBJS) $(LIBRARY) $(LDFLAGS) $(GINIT_LDLIBS) $(TARGET_RUNTIME_LD)

$(BINDIR)/ginit-netcfg: $(NETCFG_OBJS) $(LIBRARY)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $(NETCFG_OBJS) $(LIBRARY) $(LDFLAGS) $(NETCFG_LDLIBS) $(TARGET_RUNTIME_LD)

$(BINDIR)/getty: $(GETTY_OBJS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $^ $(LDFLAGS) $(TARGET_RUNTIME_LD)

$(BINDIR)/login: $(LOGIN_OBJS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $(LOGIN_OBJS) $(LDFLAGS) $(LOGIN_LDLIBS) $(TARGET_RUNTIME_LD)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

install: all
	mkdir -p $(DESTDIR)/bin $(DESTDIR)/sbin $(DESTDIR)/usr/bin $(DESTDIR)/usr/sbin
	mkdir -p $(DESTDIR)/usr/lib/ginit/services
	mkdir -p $(DESTDIR)/etc/ginit/services/system
	cp $(BINDIR)/ginit $(DESTDIR)/bin/ginit
	cp $(BINDIR)/ginit-netcfg $(DESTDIR)/bin/ginit-netcfg
	cp $(BINDIR)/login $(DESTDIR)/usr/bin/login
	cp $(BINDIR)/getty $(DESTDIR)/usr/sbin/getty
	cp boot-services.conf $(DESTDIR)/usr/lib/ginit/boot-services.conf
	cp services/*.gservice $(DESTDIR)/usr/lib/ginit/services/
	# Note: symlinks and other setup are handled by the main build script for now

clean:
	rm -rf $(OBJDIR) $(BINDIR) $(LIBDIR)

.PHONY: all clean install
