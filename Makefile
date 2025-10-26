# KVM Escape Toolkit Makefile
# Builds kernel module and userland prober tool with signing support

# Kernel module name and source
MODULE_NAME := kvm_probe_drv
MODULE_SRC := kvm_probe_drv.c
PROBER_SRC := kvm_prober.c
PROBER_EXE := kvm_prober

# Kernel build configuration
KERNEL_VERSION ?= $(uname -r)
KERNEL_DIR ?= /lib/modules/$(KERNEL_VERSION)/build
PWD := $(shell pwd)

# Signing configuration
SIGNING_KEY ?= MOK.priv
SIGNING_CERT ?= MOK.der
SIGN_TOOL := /usr/src/linux-headers-$(KERNEL_VERSION)/scripts/sign-file
KERNEL_SIG_HASH ?= sha256

# LoadPin workaround directory
MODULE_INSTALL_DIR ?= /lib/modules/$(KERNEL_VERSION)/extra

# Compiler flags
CFLAGS_user := -O2 -Wall -Wextra -g -I.

all: module prober

module: $(MODULE_NAME).ko

$(MODULE_NAME).ko: $(MODULE_SRC)
	@echo "Building kernel module from $(MODULE_SRC)..."
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

prober: $(PROBER_EXE)

$(PROBER_EXE): $(PROBER_SRC)
	@echo "Building userland prober from $(PROBER_SRC)..."
	$(CC) $(CFLAGS_user) -o $@ $^

# Signing targets
keys:
	@echo "Generating module signing keys..."
	openssl req -new -x509 -newkey rsa:2048 \
		-keyout $(SIGNING_KEY) -outform DER -out $(SIGNING_CERT) \
		-nodes -days 36500 -subj "/CN=KVM_Probe_Toolkit/"
	@echo "Keys generated: $(SIGNING_KEY) and $(SIGNING_CERT)"
	chmod 600 $(SIGNING_KEY)

sign: $(MODULE_NAME).ko
	@echo "Signing kernel module..."
	@if [ ! -f "$(SIGNING_KEY)" ] || [ ! -f "$(SIGNING_CERT)" ]; then \
		echo "Signing keys not found. Run 'make keys' first."; \
		exit 1; \
	fi
	$(SIGN_TOOL) $(KERNEL_SIG_HASH) $(SIGNING_KEY) $(SIGNING_CERT) $(MODULE_NAME).ko
	@echo "✓ Module signed successfully"

verify-module: $(MODULE_NAME).ko
	@echo "Verifying module signature..."
	@if modinfo $(MODULE_NAME).ko | grep -q "sig_id:"; then \
		echo "✓ Module is signed"; \
		echo "Signature details:"; \
		modinfo $(MODULE_NAME).ko | grep -E "sig_id|signer|sig_key|sig_hashalgo"; \
	else \
		echo "✗ Module is not signed"; \
	fi

# Test signature with better verification
test-signature: $(MODULE_NAME).ko
	@echo "=== Testing Module Signature ==="
	@echo "1. Checking module info..."
	@modinfo $(MODULE_NAME).ko
	@echo ""
	@echo "2. Checking signature details..."
	@if modinfo $(MODULE_NAME).ko | grep -q "sig_id:"; then \
		echo "✓ PKCS#7 signature found and valid"; \
		echo "✓ Signer: $$(modinfo $(MODULE_NAME).ko | grep '^signer:' | cut -d: -f2-)"; \
		echo "✓ Hash algorithm: $$(modinfo $(MODULE_NAME).ko | grep '^sig_hashalgo:' | cut -d: -f2-)"; \
	else \
		echo "✗ No valid signature found"; \
	fi

# LoadPin workaround targets
check-loadpin:
	@echo "=== LoadPin Status ==="
	@if [ -d "/sys/kernel/security/loadpin" ]; then \
		echo "LoadPin is enabled"; \
		echo "Current status: $$(cat /sys/kernel/security/loadpin/enabled 2>/dev/null || echo 'unknown')"; \
		echo "Workaround: Use 'make install-system' instead of 'make install-module'"; \
	else \
		echo "LoadPin is not enabled"; \
	fi

disable-loadpin:
	@echo "Temporarily disabling LoadPin..."
	@if [ -f "/sys/kernel/security/loadpin/enabled" ]; then \
		echo "0" | sudo tee /sys/kernel/security/loadpin/enabled; \
		echo "LoadPin disabled temporarily"; \
	else \
		echo "LoadPin control not available"; \
	fi

enable-loadpin:
	@echo "Re-enabling LoadPin..."
	@if [ -f "/sys/kernel/security/loadpin/enabled" ]; then \
		echo "1" | sudo tee /sys/kernel/security/loadpin/enabled; \
		echo "LoadPin enabled"; \
	fi

# System installation (bypasses LoadPin)
install-system: module sign
	@echo "Installing module to system directory (bypasses LoadPin)..."
	sudo mkdir -p $(MODULE_INSTALL_DIR)
	sudo cp $(MODULE_NAME).ko $(MODULE_INSTALL_DIR)/
	sudo depmod -a
	sudo modprobe $(MODULE_NAME)
	sudo chmod 666 /dev/kvm_probe_dev 2>/dev/null || true
	@echo "✓ Module installed via system path"

uninstall-system:
	@echo "Removing module from system..."
	-sudo rmmod $(MODULE_NAME) 2>/dev/null || true
	-sudo rm -f $(MODULE_INSTALL_DIR)/$(MODULE_NAME).ko
	sudo depmod -a
	-sudo rm -f /dev/kvm_probe_dev 2>/dev/null || true

# Direct installation (may be blocked by LoadPin)
install-module: module sign
	@echo "Installing module directly (may be blocked by LoadPin)..."
	sudo insmod $(MODULE_NAME).ko
	sudo chmod 666 /dev/kvm_probe_dev

uninstall-module:
	-sudo rmmod $(MODULE_NAME) 2>/dev/null || true
	-sudo rm -f /dev/kvm_probe_dev 2>/dev/null || true

load: install-system

unload: uninstall-system

install: all install-system

clean:
	@echo "Cleaning build artifacts..."
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f $(PROBER_EXE) *.o .*.cmd *.mod.c *.mod *.ko modules.order Module.symvers

distclean: clean
	rm -f $(SIGNING_KEY) $(SIGNING_CERT) *.pem *.der

security-check: $(MODULE_NAME).ko $(PROBER_EXE)
	@echo "=== Security Verification ==="
	@echo "Kernel module signature:"
	@if modinfo $(MODULE_NAME).ko | grep -q "sig_id:"; then \
		echo "✓ SIGNED - $$(modinfo $(MODULE_NAME).ko | grep '^signer:' | cut -d: -f2-)"; \
	else \
		echo "✗ UNSIGNED"; \
	fi
	@echo "LoadPin status:"
	@if [ -f "/sys/kernel/security/loadpin/enabled" ]; then \
		if [ "$$(cat /sys/kernel/security/loadpin/enabled)" = "1" ]; then \
			echo "✓ ENABLED - Use 'make install-system'"; \
		else \
			echo "○ DISABLED - Direct loading possible"; \
		fi; \
	else \
		echo "○ NOT AVAILABLE"; \
	fi

.PHONY: all module prober clean install-module uninstall-module load unload install sign keys verify-module test-signature check-loadpin disable-loadpin enable-loadpin install-system uninstall-system security-check

# Kernel module objects
obj-m := $(MODULE_NAME).o
