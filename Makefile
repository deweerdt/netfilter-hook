MODULE_NAME = hk
${MODULE_NAME}-objs := hook.o

ifneq ($(KERNELRELEASE),)

obj-m   := $(MODULE_NAME).o

else

KDIR	?= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

all: user
	$(MAKE) C=1 -C $(KDIR) M=$(PWD) modules

endif

user: user.c hook.h
	gcc -Wall -o user user.c
