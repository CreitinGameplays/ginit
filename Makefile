CXX = g++
CXXFLAGS += -Wall -Wextra -O2 -I./src
LDFLAGS = -lssl -lcrypto -lz -lzstd -ldl -lpthread

SRCDIR = src
OBJDIR = obj
BINDIR = bin
LIBDIR = lib

# Targets
TARGETS = $(BINDIR)/ginit $(BINDIR)/getty $(BINDIR)/login
LIBRARY = $(LIBDIR)/libgemcore.a

# Objects
LIB_OBJS = $(OBJDIR)/signals.o $(OBJDIR)/network.o $(OBJDIR)/user_mgmt.o
GINIT_OBJS = $(OBJDIR)/ginit.o $(OBJDIR)/gservice_parser.o $(OBJDIR)/gservice_manager.o
GETTY_OBJS = $(OBJDIR)/getty.o
LOGIN_OBJS = $(OBJDIR)/login.o

all: $(BINDIR) $(OBJDIR) $(LIBDIR) $(LIBRARY) $(TARGETS)

$(BINDIR) $(OBJDIR) $(LIBDIR):
	mkdir -p $@

$(LIBRARY): $(LIB_OBJS)
	ar rcs $@ $^

$(BINDIR)/ginit: $(GINIT_OBJS) $(LIBRARY)
	$(CXX) $(CXXFLAGS) -o $@ $(GINIT_OBJS) $(LIBRARY) $(LDFLAGS)

$(BINDIR)/getty: $(GETTY_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(BINDIR)/login: $(LOGIN_OBJS) $(LIBRARY)
	$(CXX) $(CXXFLAGS) -o $@ $(LOGIN_OBJS) $(LIBRARY) $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

install: all
	mkdir -p $(DESTDIR)/bin $(DESTDIR)/sbin
	mkdir -p $(DESTDIR)/usr/lib/ginit/services
	mkdir -p $(DESTDIR)/etc/ginit/services/system
	cp $(BINDIR)/ginit $(DESTDIR)/bin/ginit
	cp $(BINDIR)/login $(DESTDIR)/bin/login
	cp $(BINDIR)/getty $(DESTDIR)/sbin/getty
	cp services/*.gservice $(DESTDIR)/usr/lib/ginit/services/
	# Note: symlinks and other setup are handled by the main build script for now

clean:
	rm -rf $(OBJDIR) $(BINDIR) $(LIBDIR)

.PHONY: all clean install