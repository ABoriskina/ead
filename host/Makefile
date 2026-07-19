CLANG = clang
GO = go

USER_DIR = agent
BPF_DIR = ebpf
BUILD_DIR = build

INCLUDES = -I$(USER_DIR) -I$(BPF_DIR)

BPF_CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 $(INCLUDES)

BPF_SRC = $(BPF_DIR)/collector.bpf.c
BPF_OBJ = $(BUILD_DIR)/collector.bpf.o
BPF_HEADERS = \
	$(BPF_DIR)/collector.h \
	$(BPF_DIR)/collector-config.h \
	$(BPF_DIR)/vmlinux.h

USER_SRC = $(wildcard $(USER_DIR)/*.go)
USER_BIN = $(BUILD_DIR)/agent

.PHONY: all clean

all: $(BUILD_DIR) $(BPF_OBJ) $(USER_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	cp bpf-config.json $(BUILD_DIR)/bpf-config.json

$(BPF_OBJ): $(BPF_SRC) $(BPF_HEADERS)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): $(USER_SRC)
	$(GO) build -o $@ ./$(USER_DIR)

clean:
	rm -rf $(BUILD_DIR)