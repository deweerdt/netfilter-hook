EXTRA_CFLAGS+=-g -O0 -Wall
MODULE_NAME = hk
${MODULE_NAME}-objs := hook.o

ifneq ($(KERNELRELEASE),)

obj-m   := $(MODULE_NAME).o

else

KDIR	?= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)

all: user
	$(MAKE) -C $(KDIR) M=$(PWD) modules

endif

user: user.c hook.h
	gcc $(CFLAGS) -Wall -o user user.c -lpthread
