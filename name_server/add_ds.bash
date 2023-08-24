#! /bin/bash

if [[ $# < 1 ]]
then
	echo "Expected at least one argument"
	exit 1
fi

ZONEDB=$1

for ZONE in $@
do
	if [[ $ZONE = $ZONEDB ]]
	then
		continue
	fi
	while [[ ! -f /dsset/dsset-$ZONE ]]
	do
		echo "Waiting for" /dsset/dsset-$ZONE "to exist"
		sleep 1
	done
	DSREC=$(cat /dsset/dsset-$ZONE)
	egrep "$(echo -n $DSREC)" "/usr/local/etc/bind/zones/"$ZONEDB > /dev/null
	if [[ $? != 0 ]]
	then
		echo "" >> "/usr/local/etc/bind/zones/"$ZONEDB
		echo $DSREC >> "/usr/local/etc/bind/zones/"$ZONEDB
	fi
done
