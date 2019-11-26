clear
#!/bin/bash
# NextSec.vn - Secure your Web/Mobi/IoT apps from cyber-attacks - Contacts Us! We help. - thaopt@nextsec.vn


# declare some system variables
iptables="/sbin/iptables"
external=`/sbin/route | grep -i 'default' | awk '{print $NF}'`
internal="eth0"
network_addr=$(/sbin/ip route | grep default | awk '{print $3}' | cut -d"." -f1-3)
broadcast_addr="$network_addr.255"

lan_allow="1" 					# this will set allow all connection from LAN
blacklist_block="1" 				# enable block ips from blacklist
whitelist_allow="1" 				# enable allow ips from whitelist
gateway="1" 					# make this server as gateway
china_block="0" 				# block all ip from china

# allow incoming TCP
tcp_ports="80 443"		# Put a list Port here, seperated by space

# allow incoming UDP
udp_ports=""				# Put a list Port here, seperated by space

# file
black_list="blacklist.txt"
white_list="whitelist.txt"
china_zone="cn.zone"

### MAIN ###
case "$1" in
    start)
		echo "Starting firewall: "
		stop_firewall="0"
        ;;
    stop)
		echo "Stopping firewall: "
		stop_firewall="1"
        ;;
    restart)
		stop_firewall="1"
		echo "Restarting firewall: "
		stop_firewall="0"
        ;;
    *) 
        echo $"Usage: filewall.sh {start|stop|restart}"
        exit 2
esac

# check if file is found
if [ $blacklist_block = "1" ] && [ ! -f $black_list ]; then
	echo "File $black_list not found."
	exit 1
fi

if [ $china_block = "1" ] && [ ! -f $china_zone ]; then
	echo "File $china_zone not found."
	exit 1
fi

if [ $whitelist_allow = "1" ] && [ ! -f "$white_list" ]; then
	echo "File $white_list not found."
	exit 1
fi

### Start
# tuning network protection
echo 1 > /proc/sys/net/ipv4/tcp_syncookies                          # enable TCP SYN cookie protection
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route            # disable IP Source routing
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects               # disable ICMP Redirect acceptance
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter                      # enable IP spoofing protection
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts             # ignore echo broadcast requests to prevent smurf attacks
echo 1 > /proc/sys/net/ipv4/ip_forward                              # enable ip forwarding
echo "[+] Tuning Network Protection [OK]"
# delete all existing rules
$iptables -F
$iptables -X
$iptables -t nat -F
$iptables -t nat -X
$iptables -t mangle -F
$iptables -t mangle -X

$iptables -t nat -P PREROUTING ACCEPT
$iptables -t nat -P OUTPUT ACCEPT
$iptables -t nat -P POSTROUTING ACCEPT

$iptables -t mangle -P PREROUTING ACCEPT
$iptables -t mangle -P INPUT ACCEPT
$iptables -t mangle -P FORWARD ACCEPT
$iptables -t mangle -P OUTPUT ACCEPT
$iptables -t mangle -P POSTROUTING ACCEPT

echo "[+] Flushing existing rules [OK]"

if [ "$stop_firewall" = "1" ]; then
	echo "[+] Stopping the firewall [OK]"
	echo "--> The firewall has completely STOPPED [WARNING]"
	exit 0
fi

# allow loopback
$iptables -A INPUT  -i lo -j ACCEPT
$iptables -A OUTPUT -o lo -j ACCEPT

# allow all LAN connection
$iptables -A INPUT -i $internal -j ACCEPT
$iptables -A OUTPUT -o $internal -j ACCEPT

# allow incoming state RELATED,ESTABLISHED
$iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
#$iptables -A INPUT -m state --state RELATED,ESTABLISHED -m limit --limit 60/second --limit-burst 160 -j ACCEPT
# masquerading
$iptables -t nat -A POSTROUTING -o $external -j MASQUERADE 

#Invalid user-agent
iptables -A INPUT -p tcp --dport 80 -m string --algo bm --string "Mozilla/5.0 (compatible; MJ12bot/v1.4.7; http://mj12bot.com/)" -j DROP


# defaul policy
$iptables -P INPUT   ACCEPT
$iptables -P FORWARD ACCEPT
$iptables -P OUTPUT  ACCEPT

echo "[+] Setting Default Policy [OK]"

# allow good ip from whitelist file
if [ "$whitelist_allow" = "1" ]; then
	$iptables -N acceptlist
	good_ips=$(egrep -v -E "^#|^$" $white_list)
	for ip in $good_ips; do
		$iptables -A acceptlist -s $ip -j ACCEPT
	done
	$iptables -I INPUT -j acceptlist
fi

echo "[+] Adding rules: "

echo "  --> Allow Good IP From Whitelist File [OK]"

# block bad ip from blacklist file
if [ "$blacklist_block" = "1" ]; then
	$iptables -N droplist
	bad_ips=$(egrep -v -E "^#|^$" $black_list)
	for ip in $bad_ips; do
		$iptables -A droplist -s $ip -j LOG --log-prefix "=== drop blacklist :"
		$iptables -A droplist -s $ip -j DROP
	done
	$iptables -I INPUT -j droplist
fi

echo "  --> Block Bad IP From Blacklist File [OK]"

echo "  --> Blocking China IPs..."
# block china 
if [ "$china_block" = "1" ]; then
	ipset destroy china
	ipset -N china hash:net
	china_ips=$(egrep -v -E "^#|^$" $china_zone)
	for ip in $china_ips; do 
		ipset -A china $ip; 
	done
	$iptables -A INPUT -p tcp -m set --match-set china src -j LOG --log-prefix "=== drop china :"
	$iptables -A INPUT -p tcp -m set --match-set china src -j DROP
fi

echo "        -->[OK]"

# allow ping
$iptables -A INPUT -p icmp -m limit --limit 5/s -j ACCEPT
$iptables -A OUTPUT -p icmp -m limit --limit 5/s -j ACCEPT
# allow incoming SSH
#$iptables -A INPUT -i $external -p tcp --dport 22 -j ACCEPT
#$iptables -A OUTPUT -o $external -p tcp --sport 22 -j ACCEPT

$iptables -A INPUT -i $external -p udp --dport 69 -j ACCEPT

# limit https connection
$iptables -A INPUT -i $external -p tcp --syn --dport 80 -m connlimit --connlimit-above 25 --connlimit-mask 32 -j LOG --log-prefix "=== connlimit :"
$iptables -A INPUT -i $external -p tcp --syn --dport 80 -m connlimit --connlimit-above 25 --connlimit-mask 32 -j REJECT --reject-with tcp-reset

$iptables -A INPUT -i $external -p tcp --dport 80 -m state --state NEW -m recent --set 
$iptables -A INPUT -i $external -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j LOG --log-prefix "== hitcount :"
$iptables -A INPUT -i $external -p tcp --dport 80 -m state --state NEW -m recent --update --seconds 1 --hitcount 20 -j REJECT --reject-with tcp-reset

echo "  --> Limit Https Connection [OK]"

# allow udp broadcast
$iptables -A INPUT -i $external -p udp -d $broadcast_addr -j ACCEPT
$iptables -A INPUT -i $external -p udp -d 255.255.255.255 -j ACCEPT

# allow incoming TCP
for i in $tcp_ports;do
	$iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport $i -j ACCEPT;
done

echo "  --> Allow Incoming TCP [OK]"

# allow incoming UDP
for j in $udp_ports;do
	$iptables -A INPUT -p udp -m state --state NEW -m udp --dport $j -j ACCEPT;
done

echo "  --> Allow Incoming UDP [OK]"

# make sure to drop bad packages
$iptables -A INPUT -f -j DROP # Drop packages with incoming fragments
$iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP # Drop incoming malformed XMAS packets
$iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP # Drop all NULL packets
$iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP # Drop all new connection are not SYN packets

# log all the rest before dropping
$iptables -A INPUT -j LOG --log-prefix "=== IN:"
$iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited

# nat port
port_forward_tcp() {
        port=$1
        backend_ip=$2
        iptables -t nat -A PREROUTING -i $external -p tcp -m tcp --dport $port -j DNAT --to-destination $backend_ip
}

port_forward_udp() {
        port=$1
        backend_ip=$2
        iptables -t nat -A PREROUTING -i $external -p udp -m udp --dport $port -j DNAT --to-destination $backend_ip
}

## TCP forwarding - example
#port_forward_tcp 8022 10.0.17.97:8080

echo "  --> Port Forward TCP [OK]"

## UDP forwarding - example
#port_forward_udp 6192 10.0.0.92:161


echo "  --> Port Forward UDP [OK]"

### End

