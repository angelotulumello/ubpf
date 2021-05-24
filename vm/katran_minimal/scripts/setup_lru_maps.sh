#!/bin/bash
source ./DEMO_VARS

lru_maps_values=""
lru_maps_keys=""
destination_address="$(cut -d':' -f 1 <<<"$vip")"
destination_port="$(cut -d':' -f 2 <<<"$vip")"
cnt=0


echo Password: 
read -s password

for i in $host_sequence
do 
	id=$(printf '%02x 00 00 00 00 00 00 00 00 01 02 03 04 05 06 07' $cnt)
	lru_maps_values+="$id \n"
	cnt=$((cnt+1))
done

for p in $source_ports
do
	dp=$(printf "%04x" $destination_port | sed 's/\(.\{2\}\)/\1 /g')
	sp=$(printf "%04x" $p | sed 's/\(.\{2\}\)/\1 /g')

	s1=$(cut -d'.' -f 1 <<<"$source_address") 
	s2=$(cut -d'.' -f 2 <<<"$source_address") 
	s3=$(cut -d'.' -f 3 <<<"$source_address") 
	s4=$(cut -d'.' -f 4 <<<"$source_address") 

	d1=$(cut -d'.' -f 1 <<<"$destination_address") 
	d2=$(cut -d'.' -f 2 <<<"$destination_address") 
	d3=$(cut -d'.' -f 3 <<<"$destination_address") 
	d4=$(cut -d'.' -f 4 <<<"$destination_address") 

	key=$(printf "%02x %02x %02x %02x 00 00 00 00 00 00 00 00 00 00 00 00 %02x %02x %02x %02x 00 00 00 00 00 00 00 00 00 00 00 00 $sp $dp 11 00 00 00" $s1 $s2 $s3 $s4 $d1 $d2 $d3 $d4)
	lru_maps_keys+="$key \n"

done

echo "lru_map values:"
echo -e $lru_maps_values

echo "lru_map keys:"
echo -e $lru_maps_keys 

#combine values and keys
#while IFS= read -r lineK
#do 
#	while IFS= read -r lineV
#	do
#		echo "inizio"
#		echo -e $lineK
#		echo -e $lineV
#	done <<< "$lru_maps_values"
#done <<< "$lru_maps_keys"

map_ids=$(echo $password | sudo -S  bpftool map list | grep lru_hash | grep katran_lru | cut -d: -f 1)

echo "lru_map IDs:"
echo $map_ids

echo "to configure map run: " 
echo "bpftool map update id \$id key hex \$key  value hex  \$value. For example: "

echo -e "bpftool map update id ${map_ids##*$'\n'} key hex ${lru_maps_keys##*$'\n'} value hex ${lru_maps_values##*$'\n'}" | tr -d '\n' | tr -s ' '
echo -e "\n"
