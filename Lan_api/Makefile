include $(TOPDIR)/rules.mk

#定义相关信息
PKG_NAME:=Lan_api
PKG_RELEASE:=1
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/Lan_api
	SECTION:=utils
	CATEGORY:=Utilities
	TITLE:=Lan_api -- prints a snarky message
endef

define Package/Lan_api/description
	It's my first package demo.
endef

define Build/Prepare
	echo "Here is Package/Prepare"
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/Lan_api/install
	echo "Here is Package/install"
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/Lan_api $(1)/bin/
endef

$(eval $(call BuildPackage,Lan_api))

