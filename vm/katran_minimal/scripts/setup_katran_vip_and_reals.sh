#!/bin/bash
source ./DEMO_VARS

echo adding vip $vip
$go_client -A -u $vip

for i in $host_sequence
do 
	echo adding real servers $real_servers_prefix.$i
	$go_client -a -u $vip -r $real_servers_prefix.$i
done
