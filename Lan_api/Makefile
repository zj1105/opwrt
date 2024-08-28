include $(TOPDIR)/rules.mk

# Define the package name and version
PKG_NAME:=Lan_api
PKG_VERSION:=1.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_DEPENDS:=libjson-c

define Package/Lan_api
    SECTION:=utils
    CATEGORY:=Utilities
    TITLE:=Lan_api CGI
    DEPENDS:=$(PKG_DEPENDS)
endef

define Build/Compile
    echo "Compiling CGI"
	$(MAKE) -C $(PKG_BUILD_DIR) \
        CC="$(TARGET_CC)" CFLAGS="$(TARGET_CFLAGS)" \
        LDFLAGS="$(TARGET_LDFLAGS)"
endef

define Package/Lan_api/install
    echo "Installing CGI"
	$(INSTALL_DIR) $(1)/www/cgi-bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/Lan_api $(1)/www/cgi-bin/Lan_api.cgi
endef

# Define the source directory for your build
SOURCE_DIR=$(TOPDIR)/package/Lan_api/src

define Build/Configure
	mkdir -p $(PKG_BUILD_DIR)
	cp -r $(SOURCE_DIR)/* $(PKG_BUILD_DIR)/
endef

$(eval $(call BuildPackage,Lan_api))


