. ../config.mk
RV=${VERSION}
RA=amd64
wget -c http://radare.mikelloc.com/get/${RV}/radare2_${RV}_${RA}.deb
wget -c http://radare.mikelloc.com/get/${RV}/radare2-dev_${RV}_${RA}.deb
sudo apt install -y libssl-dev
sudo dpkg -i radare2_${RV}_${RA}.deb
sudo dpkg -i radare2-dev_${RV}_${RA}.deb

# install NodeJS LTS
NV=v10.15.1
NA=linux-x64
wget -c https://nodejs.org/dist/${NV}/node-${NV}-${NA}.tar.xz
cd /work
tar xJf node-${NV}-${NA}.tar.xz -C /tmp
export PATH=/tmp/node-${NV}-${NA}/bin:$PATH
[ -z "${DESTDIR}" ] && DESTDIR=/
[ -z "${R2_PLUGDIR}" ] && R2_PLUGDIR=/usr/lib/radare2/last/plugins
make R2_PLUGDIR=${R2_PLUGDIR} DESTDIR=${DESTDIR}
