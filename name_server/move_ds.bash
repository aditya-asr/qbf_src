#! /bin/bash

if [[ $# != 1 ]]
then
	echo "Expected an argument"
	exit 1
fi

cp /usr/local/etc/bind/zones/dsset-$1 /dsset/
