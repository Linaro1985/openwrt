include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=crypto-hw-eip93
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define KernelPackage/$(PKG_NAME)
  SECTION:=sys
  CATEGORY:=Kernel modules
  SUBMENU:=Cryptographic API modules
  DEPENDS:=@TARGET_ramips_mt7621 \
	+kmod-crypto-des \
	+kmod-crypto-aead \
	+kmod-crypto-authenc \
	+kmod-crypto-md5 \
	+kmod-crypto-sha1 \
	+kmod-crypto-sha256
  KCONFIG:=CONFIG_CRYPTO_HW=y
  TITLE:=EIP93 crypto HW accelerator
  FILES:=$(PKG_BUILD_DIR)/crypto-hw-eip93.ko
  AUTOLOAD:=$(call AutoLoad,09,crypto-hw-eip93)
endef

define KernelPackage/$(PKG_NAME)/description
  Kernel module to enable EIP93 crypto engine
endef

define Build/Compile
	$(KERNEL_MAKE) M=$(PKG_BUILD_DIR) modules
endef

$(eval $(call KernelPackage,$(PKG_NAME)))
