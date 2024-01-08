define Device/LinaroPackages
  # usb storage support
  DEVICE_PACKAGES += kmod-usb-storage kmod-usb-storage-uas kmod-fs-ext4 block-mount
  # netfilter nathelper
  DEVICE_PACKAGES += kmod-nf-nathelper kmod-nf-nathelper-extra
  # net tools
  DEVICE_PACKAGES += iperf3 tcpdump openssh-sftp-server pppoe-discovery
  # sys utils
  DEVICE_PACKAGES += nano mmc-utils mc shadow-utils shadow-useradd shadow-userdel shadow-usermod
  # timezones
  DEVICE_PACKAGES += zoneinfo-asia zoneinfo-europe
  # services
  DEVICE_PACKAGES += -dnsmasq dnsmasq-full stubby
  # luci theme
  DEVICE_PACKAGES += luci-theme-material
  # luci proto
  DEVICE_PACKAGES += luci-proto-wireguard
  # luci applications
  DEVICE_PACKAGES += luci-app-acme luci-i18n-acme-ru acme-acmesh-dnsapi
  DEVICE_PACKAGES += luci-app-ddns luci-i18n-ddns-ru
  DEVICE_PACKAGES += luci-app-hd-idle luci-i18n-hd-idle-ru
  DEVICE_PACKAGES += luci-app-irqbalance luci-i18n-irqbalance-ru
  DEVICE_PACKAGES += luci-app-ksmbd luci-i18n-ksmbd-ru
  DEVICE_PACKAGES += luci-app-minidlna luci-i18n-minidlna-ru
  DEVICE_PACKAGES += luci-app-usteer
  DEVICE_PACKAGES += luci-app-pbr luci-i18n-pbr-ru
endef
