CLANG = clang
GO = go

USER_DIR = agent
BPF_DIR = ebpf
BUILD_DIR = build

INCLUDES = -I$(USER_DIR) -I$(BPF_DIR)

BPF_CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 $(INCLUDES)

BPF_SRC = $(BPF_DIR)/collector.bpf.c
BPF_OBJ = $(BUILD_DIR)/collector.bpf.o
BUILD_CONFIG = $(BUILD_DIR)/bpf-config.json
BACKUP_EVENTS_CONFIG = $(BUILD_DIR)/bpf-events-backup.json
BPF_HEADERS = \
	$(BPF_DIR)/collector.h \
	$(BPF_DIR)/collector-config.h \
	$(BPF_DIR)/vmlinux.h

USER_SRC = $(wildcard $(USER_DIR)/*.go)
USER_BIN = $(BUILD_DIR)/agent

.PHONY: all clean

all: $(BUILD_DIR) $(BUILD_CONFIG) $(BACKUP_EVENTS_CONFIG) $(BPF_OBJ) $(USER_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_CONFIG): bpf-config.json | $(BUILD_DIR)
	cp $< $@

$(BACKUP_EVENTS_CONFIG): bpf-events-backup.json | $(BUILD_DIR)
	cp $< $@

$(BPF_OBJ): $(BPF_SRC) $(BPF_HEADERS)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): $(USER_SRC)
	$(GO) build -o $@ ./$(USER_DIR)

clean:
	rm -rf $(BUILD_DIR)
