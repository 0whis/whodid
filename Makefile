# whodid Makefile

CC      := gcc
CFLAGS  := -Wall -Wextra -Wpedantic -O2 \
           -D_GNU_SOURCE \
           -fstack-protector-strong \
           -D_FORTIFY_SOURCE=2 \
           -Wformat -Wformat-security \
           -Wno-format-truncation \
           -fPIE
LDFLAGS := -pie -Wl,-z,relro -Wl,-z,now

TARGET  := whodid
SRC     := whodid.c
PREFIX  := /usr/local
BINDIR  := $(PREFIX)/bin
MAN1DIR := $(PREFIX)/share/man/man1

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Build complete: ./$(TARGET)"

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	@echo "Installed: $(DESTDIR)$(BINDIR)/$(TARGET)"
	@echo ""
	@echo "Usage:  sudo whodid /path/to/watch"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	@echo "Uninstalled: $(DESTDIR)$(BINDIR)/$(TARGET)"

clean:
	rm -f $(TARGET)
