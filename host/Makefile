CLANG = clang
GO = go

BPF_CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I.

USER_DIR = agent
BPF_DIR = ebpf
BUILD_DIR = build

BPF_SRC = $(BPF_DIR)/connections.bpf.c
BPF_OBJ = $(BUILD_DIR)/connections.bpf.o

USER_SRC = $(wildcard $(USER_DIR)/*.go)
USER_BIN = $(BUILD_DIR)/agent

.PHONY: all clean

all: $(BUILD_DIR) $(BPF_OBJ) $(USER_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): $(USER_SRC)
	$(GO) build -o $@ ./$(USER_DIR)

clean:
	rm -rf $(BUILD_DIR)