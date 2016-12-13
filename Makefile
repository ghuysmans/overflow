BIN=server s-proc append.bin
all: $(BIN)
RELOC=reloc-ghs.bin reloc.bin
reloc: $(RELOC)

clean:
	rm $(BIN) $(RELOC)
%.bin: %.asm
	nasm -fbin -o $@ $<
