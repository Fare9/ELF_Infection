CC=gcc
FLAGS=-fpic -fpie -nostdlib
BIN=ilka-infector
STRIP=strip
DEBUG=-g -Wall

.PHONY: clean

all: $(BIN) $(BIN)-stripped $(BIN)-debugging

$(BIN): $(BIN).c
	$(CC) $(FLAGS) -o $@ $<

$(BIN)-stripped: $(BIN)
	$(STRIP) -o $@ $<

$(BIN)-debugging: $(BIN).c
	$(CC) $(FLAGS) $(DEBUG) -o $@ $<

clean:
	rm $(BIN)
	rm $(BIN)-stripped
	rm $(BIN)-debugging