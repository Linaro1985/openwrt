#!/bin/sh

BUILD_DATE=$(date +%y%m%d)

get_cpu_cores() {
        local n
        n=$(nproc 2>/dev/null || echo 1)
        [ $n -gt 1 ] && echo $(($n+1)) || echo $n
}

if [ "$1" != "release" ]; then
	# prepare feeds
	echo "Updating/Installing feeds"
	(./scripts/feeds update -a && ./scripts/feeds install -a) || (echo "feeds update error!" && exit 1)

	# building available configs
	for dconfig in defconfig_*;do
		# copy config
		cp -fv ${dconfig} .config
		# configure by default config
		make defconfig || (echo "make defconfig for ${dconfig} failed!" && exit 1)
		# cleaning source code
		make clean || (echo "make clean for ${dconfig} failed!" && exit 1)
		# start building
		(make -j$(get_cpu_cores) V=s) || (echo "make for ${dconfig} failed!" && exit 1)	
	done
else
	# create release dir
	[ ! -d "release/${BUILD_DATE}" ] && mkdir -p "release/${BUILD_DATE}"

	# copy firmwares to it
	FW_FILES=$(find bin/targets -type f -name "openwrt*sysupgrade.bin" -o -name "openwrt*factory.bin")
	for dfirmware in ${FW_FILES}; do
		cfilename=$(basename -- "${dfirmware}" | cut -d '-' -f5-)
		cfw=${cfilename#*_}
		cp -f "${dfirmware}" "release/${BUILD_DATE}/${cfw%%-*}-${cfw#*-}"
	done
fi
