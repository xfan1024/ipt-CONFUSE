include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ipt_CONFUSE
PKG_VERSION:=0.0
PKG_RELEASE:=0
# PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Build/description
	xxxx
endef

define Build/Compile
	$(MAKE) ARCH="$(LINUX_KARCH)" \
			CROSS_COMPILE="$(TARGET_CROSS)" \
			$(MAKE_OPTS) \
			-C "$(LINUX_DIR)" M="$(PKG_BUILD_DIR)/kmod"
	$(call Build/Compile/Default)
endef

define KernelPackage/xt_CONFUSE
	SUBMENU:=Other modules
	TITLE:=a module use to confuse udp packet
	FILES:= $(PKG_BUILD_DIR)/kmod/xt_CONFUSE.ko
	DEPENDS:= +kmod-nf-ipt
	AUTOLOAD:=$(call AutoProbe,xt_CONFUSE)
endef

define KernelPackage/xt_CONFUSE/description
	A sample kernel module.
endef

define Package/ipt_CONFUSE
	SECTION:=base
	CATEGORY:=Network
	TITLE:=ipt_CONFUSE library
	DEPENDS :=	+iptables \
     			+IPV6:ip6tables

endef

define Package/ipt_CONFUSE/install
	$(INSTALL_DIR) $(1)/usr/lib/iptables
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libipt_CONFUSE.so $(1)/usr/lib/iptables/libipt_CONFUSE.so
endef

define Build/Prepare
	echo "PKG_BUILD_DIR: $(PKG_BUILD_DIR)"
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

$(eval $(call KernelPackage,xt_CONFUSE))
$(eval $(call BuildPackage,ipt_CONFUSE))

