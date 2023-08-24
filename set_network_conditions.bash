#! /bin/bash

docker exec build-ns1_example-1 tc qdisc add dev eth0 root netem delay 10ms rate 50mbps
docker exec build-resolver-1 tc qdisc add dev eth0 root netem delay 10ms rate 50mbps
docker exec build-ns1_root-1 tc qdisc add dev eth0 root netem delay 10ms rate 50mbps
docker exec build-client1-1 tc qdisc add dev eth0 root netem delay 10ms rate 50mbps
docker exec build-client1-1 tc qdisc add dev eth1 root netem delay 10ms rate 50mbps
