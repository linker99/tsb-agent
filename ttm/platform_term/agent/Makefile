include ./rule.mk

all:
	make -C common/
	make -C core/
	make -C tools/

clean:
	make -C common/ clean
	make -C core/ clean
	make -C tools/ clean

install:
	#make -C common/ install
	make -C core/ install
	make -C tools/ install

uninstall:
	#make -C common/ uninstall
	make -C core/ uninstall
	make -C tools/ uninstall
