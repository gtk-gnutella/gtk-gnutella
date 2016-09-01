#!/bin/sh

case "$1" in
'before_install')
	mkdir -p ~/gtk-gnutella && curl ${OBJECTSTORE_URL}gtk-gnutella-jhbuild.tar.bz2 | tar -jx  -C ~/gtk-gnutella || echo "Nothing prebuild"
	curl https://git.gnome.org/browse/gtk-osx/plain/gtk-osx-build-setup.sh | sh
	rm ~/.local/bin/python2
	ln -s /usr/bin/python2.7 ~/.local/bin/python2
	cp -v osx/jhbuildrc-gtk-gnutella  ~/.jhbuildrc-gtk-gnutella && cp -v osx/gtk-gnutella.modules ~/gtk-gnutella.modules
	git clone https://github.com/jralls/gtk-mac-bundler.git
	;;
	
'install')
	export JHB=gtk-gnutella
	export PATH=$PATH:~/.local/bin/
	jhbuild --no-interact bootstrap 2>&1 | tee jhbuild-bootstrap.log | grep -e "\*\*\*" -e "Making" ; curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T jhbuild-bootstrap.log
	jhbuild --no-interact build meta-gtk-osx-bootstrap 2>&1 | tee jhbuild-meta-gtk-osx-bootstrap.log | grep -e "\*\*\*" -e "Making" ; curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T jhbuild-meta-gtk-osx-bootstrap.log
	tar -jcf gtk-gnutella-jhbuild.tar.bz2 -C ~/gtk-gnutella inst && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T gtk-gnutella-jhbuild.tar.bz2 || echo "Unable to save jhbuild build state 1."
	
	jhbuild --no-interact build meta-gtk-osx-core 2>&1 | tee jhbuild-meta-gtk-osx-core.log | grep -e "\*\*\*" -e "Making" ; curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T jhbuild-meta-gtk-osx-core.log
	tar -jcf gtk-gnutella-jhbuild.tar.bz2 -C ~/gtk-gnutella inst && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T gtk-gnutella-jhbuild.tar.bz2 || echo "Unable to save jhbuild build state 2."
	
	jhbuild --no-interact build 2>&1 | tee jhbuild-build.log | grep -e "\*\*\*" -e Making ; curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T jhbuild-build.log
	tar -jcf gtk-gnutella-jhbuild.tar.bz2 -C ~/gtk-gnutella inst && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T gtk-gnutella-jhbuild.tar.bz2 || echo "Unable to save jhbuild build state 3."
	
	pushd gtk-mac-bundler
	make install
	popd
	;;
esac