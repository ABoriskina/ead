GO = go

USER_DIR = .
BUILD_DIR = build

USER_SRC = $(wildcard $(USER_DIR)/*.go)
USER_BIN = $(BUILD_DIR)/web

.PHONY: all clean

all: $(BUILD_DIR) $(USER_BIN)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(USER_BIN): $(USER_SRC)
	$(GO) build -o $@ ./$(USER_DIR)

clean:
	rm -rf $(BUILD_DIR)