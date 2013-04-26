# Comment/uncomment the following line to disable/enable debugging
EXTRA_DEBUG = y
DEBUG = y

ETAGS=etags 

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  EXTRA_CFLAGS += -O -g -Wall -Wstrict-prototypes -DDEBUG_SLURPOE
  # "-O" is needed to expand inlines
else
  EXTRA_CFLAGS += -O2 
endif

ifeq ($(EXTRA_DEBUG),y)
  EXTRA_CFLAGS += -O -g -Wall -Wstrict-prototypes -DEXTRA_DEBUG_SLURPOE
  # "-O" is needed to expand inlines
else
  EXTRA_CFLAGS += -O2 
endif

TARGET  = v4v

EXTRA_CFLAGS += -I$(obj)/../../common -I$(obj)/../../../common 

# If KERNELRELEASE is defined, we've been invoked from the kernel build system
# and can use its language.
ifneq ($(KERNELRELEASE),)
	v4v_module-objs := v4v.o 
	obj-m := v4v_module.o 

# Otherwise we were called directly from the command line; invoke the kernel
# build system.
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.mod.c .tmp_versions modules.order Module.*

distclean: clean
	rm -rf *.ko

tags:	*.c *.h
	find . -name '*.[ch]' | etags -

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif

