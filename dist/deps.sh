RV=1.7.0-git
RA=amd64
wget -c http://www.radare.org/get/debian/radare2_${RV}_${RA}.deb
wget -c http://www.radare.org/get/debian/radare2-dev_${RV}_${RA}.deb
sudo dpkg -i radare2_${RV}_${RA}.deb
sudo dpkg -i radare2-dev_${RV}_${RA}.deb
# install NodeJS LTS
NV=v6.11.2
wget -c https://nodejs.org/dist/${NV}/node-${NV}-linux-x64.tar.xz
tar xJvf node-${NV}-linux-x64.tar.xz
export PATH=/tmp/node-${NV}:$PATH
[ -z "${DESTDIR}" ] && DESTDIR=/
[ -z "${R2_PLUGDIR}" ] && R2_PLUGDIR=/usr/lib/radare2/last/plugins
make R2_PLUGDIR=${R2_PLUGDIR} DESTDIR=${DESTDIR}
