#!/bin/bash

# https://github.com/Naskassoff/NASKASS_TOOLS1.git

if [[ $(uname -o) == *'Android'* ]];then
	AUTOPHISHER_ROOT="/data/data/com.termux/files/usr/opt/NASKASS_TOOLS1"
else
	export NASKASS_TOOLS1="/opt/NASKASS_TOOLS1"
fi

if [[ $1 == '-h' || $1 == 'help' ]]; then
	echo "To run NASKASS_TOOLS1 type \`NASKASS_TOOLS1\` in your cmd"
	echo
	echo "Help:"
	echo " -h | help : Print this menu & Exit"
	echo " -c | auth : View Saved Credentials"
	echo " -i | ip   : View Saved Victim IP"
	echo
elif [[ $1 == '-c' || $1 == 'auth' ]]; then
	cat $NASKASS_TOOLS1/auth/usernames.dat 2> /dev/null || {
		echo "No Credentials Found !"
		exit 1
	}
elif [[ $1 == '-i' || $1 == 'ip' ]]; then
	cat $NASKASS_TOOLS1/auth/ip.txt 2> /dev/null || {
		echo "No Saved IP Found !"
		exit 1
	}
else
	cd $NASKASS_TOOLS1
	bash ./NASKASS_TOOLS1.sh
fi
