obj-$(CONFIG_SECURITY_LSM_WRAP) := lsmwrap.o

export CONFIG_SECURITY_LSM_WRAP=m

lsmwrap-y := lsm-wrap.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	$(RM) *~

.PHONY: all clean
