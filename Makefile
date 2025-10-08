ifneq ($(MAKECMDGOALS),clean)

CFLAGS := -std=c99 -Wall -Wextra -Wpedantic -Werror

ifeq ($(CONFIGURATION), debug)
	CFLAGS := $(CFLAGS) -g -D_DEBUG -O0
else
ifeq ($(CONFIGURATION), release)
	CFLAGS := $(CFLAGS) -DNDEBUG -O2
else
	@echo "[ERROR] Unknown configuration: $(CONFIGURATION)" >&2
	@exit 1
endif
endif

ifeq ($(PLATFORM), x86)
	CFLAGS := $(CFLAGS) -m32
    LFLAGS := -m32
else
ifeq ($(PLATFORM), x64)
	CFLAGS := $(CFLAGS) -m64
    LFLAGS := -m64
else
	@echo "[ERROR] Unknown platform: $(PLATFORM)" >&2
	@exit 1
endif
endif

endif

SRC_DIR := src
OBJ_DIR := obj/$(CONFIGURATION)/$(PLATFORM)
BIN_DIR := bin/$(CONFIGURATION)/$(PLATFORM)

SRC_FILES := $(shell find $(SRC_DIR) -name '*.c')
OBJ_FILES := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC_FILES))
BIN_FILES := $(BIN_DIR)/aes

all: $(BIN_FILES)

$(BIN_FILES): $(OBJ_FILES)
	@mkdir -p $(BIN_DIR)
	gcc $(LFLAGS) -o $@ $^

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	gcc $(CFLAGS) -c $< -o $@

clean:
	rm -rf obj bin

.PHONY: all clean
