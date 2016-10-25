#!/bin/bash
ADB_GO="$HOME/android/platform-tools/adb"
$ADB_GO connect 192.168.56.10
$ADB_GO root
echo 'Testing ping...'
$ADB_GO shell 'ping -c 10 8.8.8.8'
echo 'Getting public IP...'
$ADB_GO shell "wget -qO- http://153.121.72.212 | grep -Eo 'ip_address\">[^<]+<' | grep -Eo '[0-9\.]+'"
