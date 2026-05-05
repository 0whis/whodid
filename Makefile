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

.PHONY: all clean install uninstall deb rpm appimage aur

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
	@echo "Build complete: ./$(TARGET)"

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)
	@echo "Installed: $(DESTDIR)$(BINDIR)/$(TARGET)"
	install -d $(DESTDIR)$(MAN1DIR)
	install -m 644 whodid.1 $(DESTDIR)$(MAN1DIR)/whodid.1
	@echo "Installed: $(DESTDIR)$(MAN1DIR)/whodid.1"
	@echo ""
	@echo "Usage:  sudo whodid /path/to/watch"
	@echo "Manual: man whodid"

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)
	@echo "Uninstalled: $(DESTDIR)$(BINDIR)/$(TARGET)"
	rm -f $(DESTDIR)$(MAN1DIR)/whodid.1
	@echo "Uninstalled: $(DESTDIR)$(MAN1DIR)/whodid.1"

deb: $(SRC)
	@bash build-deb.sh

rpm: $(SRC)
	@bash build-rpm.sh

appimage: $(SRC)
	@bash build-appimage.sh

aur: $(SRC)
	@bash build-aur.sh

clean:
	rm -f $(TARGET)
