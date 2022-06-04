include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ipt_CONFUSE
PKG_VERSION:=0.0
PKG_RELEASE:=0
# PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Build/Prepare
	echo "PKG_BUILD_DIR: $(PKG_BUILD_DIR)"
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) ARCH="$(LINUX_KARCH)" \
			CROSS_COMPILE="$(TARGET_CROSS)" \
			$(MAKE_OPTS) \
			-C "$(LINUX_DIR)" M="$(PKG_BUILD_DIR)/kmod"
	$(call Build/Compile/Default)
endef

define Package/iptables-mod-confuse
	SECTION:=net
	CATEGORY:=Network
	SUBMENU:=Firewall
	TITLE:=confuse iptables extension
	DEPENDS :=	+iptables \
     			+IPV6:ip6tables
endef

define Package/iptables-mod-confuse/install
	$(INSTALL_DIR) $(1)/usr/lib/iptables
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/libipt_CONFUSE.so $(1)/usr/lib/iptables/libipt_CONFUSE.so
endef

define Package/iptables-mod-confuse/description
	iptables module: confuse udp packet to avoid deep-packet-inspection
endef

define KernelPackage/xt_CONFUSE
	SUBMENU:=Netfilter Extensions
	TITLE:=confuse netfilter module
	FILES:= $(PKG_BUILD_DIR)/kmod/xt_CONFUSE.ko
	DEPENDS:= +kmod-nf-ipt
	AUTOLOAD:=$(call AutoProbe,xt_CONFUSE)
endef

define KernelPackage/xt_CONFUSE/description
	kernel module: confuse udp packet to avoid deep-packet-inspection
endef

$(eval $(call KernelPackage,xt_CONFUSE))
$(eval $(call BuildPackage,iptables-mod-confuse))

