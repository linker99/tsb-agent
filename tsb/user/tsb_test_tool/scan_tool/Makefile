
CROSS_COMPILE ?=
CC:= $(CROSS_COMPILE)gcc -g
LD:= $(CROSS_COMPILE)ld

all:
	$(CC) whitelist_product.c -o whitelist_product

clean:
	rm -f whitelist_product
