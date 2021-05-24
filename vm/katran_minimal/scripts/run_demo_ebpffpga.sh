#!/bin/bash
source ./DEMO_VARS

usage () {

	echo "wrong number of arguments. syntax:" 
	echo "run_demo_ebpffpga.sh <defaul_gw_mac> <interface>"
	echo "or"
	echo "run_demo_ebpffpga.sh halt"
	exit 1
}

close_demo_screen() {
	if [ -z "$1" ] 
	then
		echo "no active demo_katran_ebpffpga screen sessions..." 
		return 0
	fi

	echo "closing demo_katran_ebpffpga screen session with pid $1"
	screen -X -S "demo_katran_ebpffpga" -t "GRPC Server" stuff "^C"
	screen -X -S "demo_katran_ebpffpga" -t "ercole" stuff "exit\n"
	screen -X -S "demo_katran_ebpffpga" -t "katran" stuff "exit\n"
	screen -X -S "demo_katran_ebpffpga" -t "demons" stuff "exit\n"

	echo "waiting for the GRPC Server to shut down..."
	sleep 10

	for i in $(screen -ls) 
	do
        	if [[ $i == *"demo_katran_ebpffpga"*  ]]
		then
			kill -9 $1
			sleep 1
			screen -wipe $1
		fi
	done
}

active_screens=$(screen -ls)

for i in $active_screens 
do 
	if [[ $i == *"demo_katran_ebpffpga"* ]] 
	then 
		katran_screen_pid="$(cut -d'.' -f 1 <<<"$i")"
	fi
done

if [ "$1" == "halt" ] 
then
	close_demo_screen $katran_screen_pid
	exit 0
elif [ "$#" ==  "2" ]
then
	default_gw_mac=$1
	interface=$2
else
	usage
fi

if [[ ! -z "$katran_screen_pid" ]]
then
	echo "there is another demo screen session running... closing it..."
	close_demo_screen $katran_screen_pid
fi

echo Password: 
read -s password

echo "setting up screen: startin katran_server_grpc... "
screen -dmS demo_katran_ebpffpga -T xterm -t "GRPC Server" sh -c 'echo ${0} | sudo -S ${4} -balancer_prog ${3} -default_mac $1 -forwarding_cores=0,1,2,3  -intf=$2 -lru_size=10000 -hc_forwarding=false; exec bash' "$password" "$default_gw_mac" "$interface" "$ebpf_prog" "$katran_server_grpc_exe"

sleep 1
echo "opening a remote shell in demons... "
screen -T xterm -S "demo_katran_ebpffpga" -X screen screen -t "demons" sh -c 'ssh demons' 

sleep 1
echo "opening a remote shell in ercole... "
screen -T xterm -S "demo_katran_ebpffpga" -X screen screen -t "ercole" sh -c 'ssh ercole' 
sleep 1
screen -X -S "demo_katran_ebpffpga" -t "ercole" stuff "cd DEMO\nsudo python ip_forge.py -d ciao -i eno1 -p udp 192.168.122.1:44436 10.255.255.254:9998"

sleep 1
echo "configuring katran via go_glient... "
screen -T xterm -S "demo_katran_ebpffpga" -X screen screen -t "katran" sh -c 'echo configuring katran; sleep 3;./setup_katran_vip_and_reals.sh; exec bash' 

sleep 1
echo "running tcpdump on ercole"
screen -T xterm -S "demo_katran_ebpffpga" -X screen screen -t "tcpdump" sh -c 'ssh ercole' 
sleep 2
screen -X -S "demo_katran_ebpffpga" -t "ercole" stuff "sudo tcpdump -ni any proto 4\n"

echo done! run \"screen -r -x demo_katran_ebpffpga\" to enter the screen session
