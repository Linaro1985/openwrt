#!/bin/sh

# Remove old archives
rm -f *.zip

# Scan and create archives
FW_FILES=$(find bin/targets/mediatek/filogic -type f -name "*-sysupgrade.bin")
for dfirmware in ${FW_FILES}; do
	cfilename=$(basename -- "${dfirmware}" | cut -d '-' -f5-)
	7z a -tzip "${cfilename}.zip" "./${dfirmware}"
done
