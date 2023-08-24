#! /bin/bash

# We should only ever be installing the trust anchor for root
# so for now it's hard-coded. This may need to change in the future

function trust_anchor_installed() {
	egrep "trust-anchors" /usr/local/etc/named.conf > /dev/null
	if [[ $? != 0 ]]
	then
		echo 1
	else
		echo 0
	fi
}

function remove_all_trust_anchors() {
	if [[ $(trust_anchor_installed) = 0 ]]
	then
		echo here
		LINENUM=$(egrep -n "trust-anchors" /usr/local/etc/named.conf | cut -d ':' -f 1 | head -n 1)
		LINENUM=$(expr $LINENUM - 1 )
		echo $LINENUM
		cat /usr/local/etc/named.conf
		head -n $LINENUM /usr/local/etc/named.conf >| /usr/local/etc/named.conf.tmp
		mv /usr/local/etc/named.conf.tmp /usr/local/etc/named.conf
		echo "----------------------"
		cat /usr/local/etc/named.conf
	fi
}

function install_trust_anchor() {
	remove_all_trust_anchors
	while [[ ! -f /dsset/dsset-. ]]
	do
		echo "Waiting for /dsset/dsset-. to be generated"
		sleep 1
	done
	DSROOT=$(cat /dsset/dsset-. | awk -F'DS' '{print $2}' | awk -F ' ' '{print $1" "$2" "$3" \""$4" "$5"\";"}')
	echo "" >> /usr/local/etc/named.conf
	echo "trust-anchors {" >> /usr/local/etc/named.conf
	echo "	. static-ds "$DSROOT >> /usr/local/etc/named.conf
	echo "};" >> /usr/local/etc/named.conf
}

install_trust_anchor
