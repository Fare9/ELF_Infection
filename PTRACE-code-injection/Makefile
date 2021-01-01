CC=gcc
FLAGS=-fpic -fpie -nostdlib
INJECTOR=code_inject
PAYLOAD=payload
HOST=host

all: $(INJECTOR) $(PAYLOAD) $(HOST)

$(INJECTOR): $(INJECTOR).c
	$(CC) -o $@ $<

$(PAYLOAD): $(PAYLOAD).c
	$(CC) $(FLAGS) -o $@ $<

$(HOST): $(HOST).c 
	$(CC) -o $@ $<

.PHONY: clean

clean:
	rm $(INJECTOR)
	rm $(PAYLOAD)
	rm $(HOST)