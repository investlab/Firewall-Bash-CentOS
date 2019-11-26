# Tool for setting up your firewall based on iptables

## Setup
- # Install ipset: #install ipset package -y

## Files
- firewall.sh: main script, need to run
- blacklist.txt: list of bad ips will be blocked (one ip/network per line)
- whitelist.txt: list of good ips will be accepted (one ip/network per line)
- cn.zone: list of China IP range.

## Usage
- Edit internal, tcp-udp port.... in firewall.sh
- Add ip address to blacklist.txt, whitelist.txt if you have
- Start firewall: #sudo sh firewall.sh start
- Stop firewall: # sudo sh firewall.sh stop
- Start firewall, and stop it after 5 minutes (testing mode): # sudo sh firewall.sh start; (sleep 300; sudo sh firewall.sh stop) &

## NextSec
- Email: thaopt@nextsec.vn