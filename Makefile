KERNELDIR ?= /lib/modules/$(shell uname -r)/build

all default: modules
install: module_install
modules module_install clean help:
	${MAKE} -C $(KERNELDIR) M=$(shell pwd) $@

appkmsg-objs := appkmsg_base.o appkmsg_cdev.o appkmsg_crypto.o \
                appkmsg_data.o appkmsg_params.o appkmsg_lib.o

obj-m += appkmsg.o
