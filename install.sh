#!/bin/bash

if ! [[ $EUID == 0 ]]; then
   echo "[*] This script must be run as root" 1>&2
   exit 1
fi

echo -e "[*] Installing required software. Please press [ENTER] to continue";
read continue

#Install required software
if [ ! -f $HOME/.mobilesandbox.txt ]; then
	apt-get install python python-pip virtualbox postgresql python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev 		libjpeg-dev tcpdump libcap2-bin automake autoconf libtool -y
	#setting for tcpdump to run as root
	setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

	touch $HOME/.mobilesandbox.txt
else
	echo -e "[*] This script was already executed and all required applications should be installed. If you want to re-run the installation please delete the .mobilesandbox.txt in your root folder"
fi 

echo -e "Please enter the full path to your requirements.txt (eg. /home/MS/requirements.txt) and press [ENTER]";

read requirements

if ! [ $requirements == "" ]; then
	pip install -r $requirements
	BUILD_LIB=1 pip install ssdeep
	wget http://chilkatdownload.com/9.5.0.65/chilkat-9.5.0-python-2.7-x86_64-linux.tar.gz
	tar -xvzf chilkat-9.5.0-python-2.7-x86_64-linux.tar.gz
	cd chilkat-9.5.0-python-2.7-x86_64-linux && python installChilkat.py 
	rm -rf chilkat-9.5.0-python-2.7-x86_64-linux*
else
	echo -e "[*] You did not provide the requirements file!\n  exit installation routine";
	exit 1
fi

echo -e "\n\n"
echo -e "[*] Installation is finished!"
echo -e "[*] You can now start to configure cuckoo, postgresql, sentry and mobilesanbox."
exit 1 


