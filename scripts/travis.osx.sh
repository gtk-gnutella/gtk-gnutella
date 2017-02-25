#!/bin/sh
bold=$(tput bold)
normal=$(tput sgr0)

case "$1" in
'before_install')
	brew remove --force $(brew list) --ignore-dependencies

	[ -n "${OBJECTSTORE_URL}" ] && mkdir -p ~/gtk-gnutella && curl ${OBJECTSTORE_URL}gtk-gnutella-jhbuild.tar.gz | tar -zx  -C ~/gtk-gnutella || echo "Nothing prebuild"
	curl https://git.gnome.org/browse/gtk-osx/plain/gtk-osx-build-setup.sh | sh
	cp -v osx/jhbuildrc-gtk-gnutella  ~/.jhbuildrc-gtk-gnutella && cp -v osx/gtk-gnutella.modules ~/gtk-gnutella.modules
	git clone https://github.com/jralls/gtk-mac-bundler.git
	;;
	
'install')
	export JHB=gtk-gnutella
	export PATH=$PATH:~/.local/bin/

	echo "jhbuild ${bold}bootstrap${normal}"
	jhbuild --no-interact bootstrap 2>&1 | tee jhbuild-bootstrap.log | grep -e "\*\*\*" -e "Making"
	[ -n "${OBJECTSTORE_URL}" ] && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T jhbuild-bootstrap.log

	echo "jhbuild ${bold}meta-gtk-osx-bootstrap${normal}"
	jhbuild --no-interact build meta-gtk-osx-bootstrap 2>&1 | tee jhbuild-meta-gtk-osx-bootstrap.log | grep -e "\*\*\*" -e "Making"
	[ -n "${OBJECTSTORE_URL}" ] && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T jhbuild-meta-gtk-osx-bootstrap.log
	[ -n "${OBJECTSTORE_URL}" ] && tar -zcf gtk-gnutella-jhbuild.tar.gz -C ~/gtk-gnutella inst && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T gtk-gnutella-jhbuild.tar.gz || echo "Unable to save jhbuild build state 1."
	
	echo "jhbuild ${bold}meta-gtk-osx-core${normal}"
	jhbuild --no-interact build meta-gtk-osx-core 2>&1 | tee jhbuild-meta-gtk-osx-core.log | grep -e "\*\*\*" -e "Making"
	[ -n "${OBJECTSTORE_URL}" ] && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T jhbuild-meta-gtk-osx-core.log
	[ -n "${OBJECTSTORE_URL}" ] && tar -zcf gtk-gnutella-jhbuild.tar.gz -C ~/gtk-gnutella inst && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T gtk-gnutella-jhbuild.tar.gz || echo "Unable to save jhbuild build state 2."
	
	echo "jhbuild ${bold}build${normal}"
	jhbuild --no-interact build 2>&1 | tee jhbuild-build.log | grep -e "\*\*\*" -e Making
	curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T jhbuild-build.log
	tar -zcf gtk-gnutella-jhbuild.tar.bz2 -C ~/gtk-gnutella inst && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T gtk-gnutella-jhbuild.tar.gz || echo "Unable to save jhbuild build state 3."
	
	pushd gtk-mac-bundler
	make install
	popd
	;;
esac
