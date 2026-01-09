CC = cc
CFLAGS = -std=c99 -Wall -Wextra -Werror -O2
LDFLAGS = -lcrypto

BIN=gnu-totp
SRC=main.c

.PHONY: all clean

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(BIN)
