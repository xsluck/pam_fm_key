PROJECT_ROOT = $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SOURCE = $(PROJECT_ROOT)pam_fm_key.c
all:
#	gcc $(SOURCE) -fPIC -shared -o pam_fm_key.so -l USBKEYapi
	gcc -fPIC -shared -o pam_fm_key.so pam_fm_key.c -lpam -lUSBKEYapi -Wattributes
	gcc -g fm_key_test.c -o fm_key_test -lUSBKEYapi -Wattributes
	gcc -o pam_test pam_test.c -lpam -lpam_misc
clean:
	rm -f pam_fm_key.so pam_fm_key.o fm_key_test pam_test
install:
	chmod 644 pam_fm_key.so
	cp -f pam_fm_key.so  /usr/lib/x86_64-linux-gnu/security/
	cp -f fm_key_test /usr/bin/
	cp -f pam_test /usr/bin/