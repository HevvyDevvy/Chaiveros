# Ransomware Defense — Linux Kernel Module Build
# ------------------------------------------------
# Requires: linux-headers matching the running kernel
#   Debian/Ubuntu:  sudo apt install linux-headers-$(uname -r)
#   Fedora/RHEL:    sudo dnf install kernel-devel
#
# Usage:
#   make          — build the module
#   make clean    — remove build artefacts
#   make install  — load the module (requires root)
#   make remove   — unload the module (requires root)

MODULE_NAME  := encryption_scanner
obj-m        += $(MODULE_NAME).o

# Source rename: Linux-Kernel-Scanner.c → encryption_scanner.c
# (kernel build system requires source and module name to match)
$(MODULE_NAME).o: Linux-Kernel-Scanner.c
	cp Linux-Kernel-Scanner.c $(MODULE_NAME).c

KDIR  := /lib/modules/$(shell uname -r)/build
PWD   := $(shell pwd)

.PHONY: all clean install remove

all: $(MODULE_NAME).o
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f $(MODULE_NAME).c

install: all
	@echo "Loading $(MODULE_NAME) kernel module..."
	sudo insmod $(MODULE_NAME).ko
	@echo "Module loaded. Check dmesg for output."

remove:
	@echo "Unloading $(MODULE_NAME) kernel module..."
	sudo rmmod $(MODULE_NAME) || true
	@echo "Module unloaded."

# DKMS target — installs via DKMS so the module survives kernel upgrades
dkms-install:
	sudo dkms add .
	sudo dkms build $(MODULE_NAME)/$(shell git describe --tags --always)
	sudo dkms install $(MODULE_NAME)/$(shell git describe --tags --always)
