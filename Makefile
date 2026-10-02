# Makefile for LabPulse Step 2 Core Network Protocols
CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -I./c_src
BIN_DIR = bin
TARGET = $(BIN_DIR)/labpulse_monitor

ifeq ($(OS),Windows_NT)
    LIBS = -lws2_32 -liphlpapi
    TARGET_EXT = $(TARGET).exe
    MKDIR = if not exist $(BIN_DIR) mkdir $(BIN_DIR)
    RM = del /Q /F
else
    LIBS = -lpthread
    TARGET_EXT = $(TARGET)
    MKDIR = mkdir -p $(BIN_DIR)
    RM = rm -f
endif

SOURCES = c_src/main.c \
          c_src/icmp.c \
          c_src/udp.c \
          c_src/tcp.c

all: $(TARGET_EXT)

$(TARGET_EXT): $(SOURCES)
	@$(MKDIR)
	$(CC) $(CFLAGS) $(SOURCES) $(LIBS) -o $(TARGET_EXT)
	@echo "[+] Built: $(TARGET_EXT)"

clean:
	$(RM) $(BIN_DIR)\* 2>nul || true

.PHONY: all clean
