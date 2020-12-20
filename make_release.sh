#!/bin/sh

OWRT="19.07.5"

# Remove old archives
rm -f *.zip

# Create Tuoshi UBOOT
pushd fwbin
7z a -tzip ../TuoshiTS7620N_UBOOT.zip uboot_ts7620n.*
popd

# Create C20v1 Tftp
cat fwbin/uboot_c20v1.bin bin/targets/ramips/mt7620/openwrt-${OWRT}-ramips-mt7620-tplink_c20-v1-squashfs-factory.bin > ArcherC20V1_tp_recovery.bin
7z a -sdel -tzip TPLinkArcherC20V1_Tftp.zip ArcherC20V1_tp_recovery.bin

# Create C20v4 Tftp
cp -f bin/targets/ramips/mt76x8/openwrt-${OWRT}-ramips-mt76x8-tplink_c20-v4-squashfs-tftp-recovery.bin tp_recovery.bin
dd if=fwbin/uboot_c20v4.bin of=tp_recovery.bin bs=512 seek=0 conv=notrunc,sync
7z a -sdel -tzip TPLinkArcherC20V4_Tftp.zip tp_recovery.bin

# Create C20v1 Sysupgrade
pushd bin/targets/ramips/mt7620
7z a -tzip ../../../../TPLinkArcherC20V1_UpgradeOnlyFromOpenwrt.zip openwrt-${OWRT}-ramips-mt7620-tplink_c20-v1-squashfs-sysupgrade.bin

# Create Tuoshi TS7620N Sysupgrade
7z a -tzip ../../../../TuoshiTS7620N.zip openwrt-${OWRT}-ramips-mt7620-tuoshi_ts7620n-squashfs-sysupgrade.bin
popd

# Create C20v4 Sysupgrade
pushd bin/targets/ramips/mt76x8
7z a -tzip ../../../../TPLinkArcherC20V4_UpgradeOnlyFromOpenwrt.zip openwrt-${OWRT}-ramips-mt76x8-tplink_c20-v4-squashfs-sysupgrade.bin

# Create C20v5 Sysupgrade
7z a -tzip ../../../../TPLinkArcherC20V5_UpgradeOnlyFromOpenwrt.zip openwrt-${OWRT}-ramips-mt76x8-tplink_c20-v5-squashfs-sysupgrade.bin
popd

# Create C20v5 Firmwares
cat <<EOF >readme.txt
openwrt-${OWRT}-ramips-mt76x8-tplink_c20-v5-squashfs-factory.bin - image for installing openwrt via tplink webinterface
tp_recovery.bin - image for installing openwrt via tftp method
EOF
cat fwbin/uboot_c20v5_tpl.bin bin/targets/ramips/mt76x8/openwrt-${OWRT}-ramips-mt76x8-tplink_c20-v5-squashfs-sysupgrade.bin > openwrt-${OWRT}-ramips-mt76x8-tplink_c20-v5-squashfs-factory.bin
dd if=fwbin/uboot_c20v5_tpl.bin of=uboot_c20v5.bin bs=512 skip=1 conv=sync
cat fwbin/uboot_c20v5_factory.bin uboot_c20v5.bin bin/targets/ramips/mt76x8/openwrt-${OWRT}-ramips-mt76x8-tplink_c20-v5-squashfs-sysupgrade.bin > tp_recovery.bin
rm -f uboot_c20v5.bin
7z a -sdel -tzip TPLinkArcherC20V5.zip readme.txt openwrt-${OWRT}-ramips-mt76x8-tplink_c20-v5-squashfs-factory.bin tp_recovery.bin
