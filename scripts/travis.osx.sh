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

	jhb_actions_all=("bootstrap" "meta-gtk-osx-bootstrap" "meta-gtk-osx-core" "build")
	jhb_actions=("${jhb_actions_all[@]}")
	[ -f ~/gtk-gnutella/jhbuild-state ] && source ~/gtk-gnutella/jhbuild-state

	if [ -n "${jhbuild_done}" ]
	then
		while [ "${jhb_actions}" != "${jhbuild_done}" ]
		do
			jhb_actions=( "${jhb_actions[@]:1}" )
		done

		jhb_actions=( "${jhb_actions[@]:1}" )
	fi

	for jhbuild_action in ${jhb_actions[@]}
	do
		echo "jhbuild ${bold}${jhbuild_action}${normal}"
		jhbuild --min-age=24h --no-interact ${jhbuild_action} 2>&1 | tee "jhbuild-${jhbuild_action}.log" | grep -e "\*\*\*" -e "Making"
		echo "jhbuild_done=${jhbuild_action}" > ~/gtk-gnutella/jhbuild-state
		[ -n "${OBJECTSTORE_URL}" ] && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T jhbuild-${jhbuild_action}.log
		[ -n "${OBJECTSTORE_URL}" ] && tar -zcf gtk-gnutella-jhbuild.tar.gz -C ~/gtk-gnutella jhbuild-state inst source && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T gtk-gnutella-jhbuild.tar.gz || echo "Unable to save jhbuild build state ${jhbuild_action}."
	done

	# All actions were already done, update only required
	if [ ${#jhb_actions[@]} -eq 0 ]
	then
		jhbuild --min-age=24h --no-interact ${jhb_actions_all[@]} 2>&1 | tee "jhbuild-update.log" | grep -e "\*\*\*" -e "Making"
		[ -n "${OBJECTSTORE_URL}" ] && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T jhbuild-update.log
		[ -n "${OBJECTSTORE_URL}" ] && tar -zcf gtk-gnutella-jhbuild.tar.gz -C ~/gtk-gnutella jhbuild-state inst source && curl -X PUT --user ${OBJECTSTORE_USER}:${OBJECTSTORE_SECRET} ${OBJECTSTORE_URL} -T gtk-gnutella-jhbuild.tar.gz || echo "Unable to save jhbuild build state ${jhbuild_action}."
	fi
	
	pushd gtk-mac-bundler
	make install
	popd
	;;
esac
