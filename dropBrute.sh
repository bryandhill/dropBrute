#!/bin/sh
#
# dropBrute.sh by robzr
#
# minimalist OpenWRT/dropbear ssh brute force attack banning script
#
# Installation steps:
#
# 1) Optionally edit the variables in the header of this script to customise
#    for your environment
#
# 2) Setup fw4 custom scripts
#
#    mkdir -p /usr/share/nftables.d/table-post/
#    mkdir -p /usr/share/nftables.d/chain-pre/input_wan/
#    echo 'jump drop_brute' > /usr/share/nftables.d/chain-pre/input_wan/inject_jump_drop_brute.nft
#    echo -e 'chain drop_brute {\n    comment "Drop Brute Block Chain"\n}\n' > /tmp/create_drop_brute.nft
#    ln -s /tmp/create_drop_brute.nft /usr/share/nftables.d/table-post/create_drop_brute.nft
#
# 3) Run the script periodically out of cron:
#
#    echo '*/10 * * * * /usr/sbin/dropBrute.sh 2>&1 >> /tmp/dropBrute.log' >> /etc/crontabs/root
#
# 4) If cron is not enabled, you'll also need to run the following:
#
#    /etc/init.d/cron enable && /etc/init.d/cron start
#
#
# To whitelist hosts or networks, simply add a manual entry to the lease
# file with a leasetime of -1.  This can be done with the following syntax:
#
#    echo -1 192.168.1.0/24 >> /tmp/dropBrute.leases
#
# A static, or non-expiring blacklist of a host or network can also be
# added, just use a lease time of 0.  This can be done with the following syntax:
#
#    echo 0 1.2.3.0/24 >> /tmp/dropBrute.leases

# Determines whether the status output is printed when nothing happens
alwaysPrintStatus=0

# How many bad attempts before banning. Only the log entries from the
# current day are checked.
allowedAttempts=10

# How long IPs are banned for after the current day ends.
# default is 7 days
secondsToBan=$((7*60*60*24))

# the "lease" file
#leaseFile=/tmp/dropBrute.leases    # does not persist across reboots
leaseFile=/etc/dropBrute.leases   # persists across reboots


# You can put default leasefile entries in the following space.
# Syntax is simply "leasetime _space_ IP_or_network".  A leasetime of -1 is a
# whitelist entry, and a leastime of 0 is a permanent blacklist entry.
MYNET=$(/bin/ipcalc.sh `uci get network.lan.ipaddr` `uci get network.lan.netmask` | awk -F= '/^NETWORK=/ {printf $2."/"} /^PREFIX=/ {print $2}')
[ -f $leaseFile ] || cat <<__EOF__>>$leaseFile
-1 $MYNET
__EOF__

# End of user customizable variables (unless you know better :) )

[ `date +'%s'` -lt 1320000000 ] && echo System date not set, aborting. && exit -1

today=`date +'%a %b %d' | sed -E 's/0(\d)/ \1/g'`
now=`date +'%s'`
nowPlus=$((now + secondsToBan))

activityCounter=0
logLine()
{
  [ $((activityCounter++)) -eq 0 ] && echo Running dropBrute on `date` \($now\)
  [ "$1" == "" ] || echo "$1"
}
badIPS=''
# Method for 22.03 dropbear 'login attempt for nonexistent user'
badIPS=$(echo "$badIPS";logread|egrep "^$today"|fgrep dropbear|egrep -i 'login attempt for nonexistent user' -B 1 | egrep -i 'Child connection from ' | sed 's/^.*from //'|sed 's/:.*$//')

# Method for 22.03 dropbear 'Bad password attempt'
badIPS=$(echo "$badIPS";logread|egrep "^$today"|fgrep dropbear|egrep -i 'bad password attempt for ' | sed 's/^.*from //'|sed 's/:.*$//')

# Method from around 2020 for openvpn attacks
badIPS=$(echo "$badIPS";logread|egrep "^$today"|fgrep openvpn|egrep 'indicate a possible active attack'\|'Fatal TLS error (check_tls_errors_co), restarting'|sed 's/.*openvpn[^:]*: \([^ ]*\):.*/\1/')

# Method for 22.03 sshd 'failed password for'
badIPS=$(echo "$badIPS";logread|egrep "^$today"|fgrep sshd|egrep -i 'failed password for' | sed 's/^.*from //'|sed 's/.port.*$//')

# Method for 22.03 ssh 'Unable to negotiate with'
badIPS=$(echo "$badIPS";logread|egrep "^$today"|fgrep sshd|egrep -i 'unable to negotiate with' | sed 's/^.*with//'|sed 's/.port.*$//')

# Method for 22.03 ssh 'Invalid user'
badIPS=$(echo "$badIPS";logread|egrep "^$today"|fgrep sshd|egrep -iv 'Connection'|egrep -iv 'Disconnected'|egrep -i 'invalid user' | sed 's/^.*from//'|sed 's/.port.*$//')

# find new badIPs
for badIP in `echo "$badIPS"|sort -u` ; do
  found=`echo "$badIPS"|fgrep $badIP|wc -l`
  if [ $found -gt $allowedAttempts ] ; then
    if [ `egrep \ $badIP\$ $leaseFile|wc -l` -gt 0 ] ; then
       [ `egrep \ $badIP\$ $leaseFile|cut -f1 -d\ ` -gt 0 ] && sed -i 's/^.* '$badIP\$/$nowPlus\ $badIP\/ $leaseFile
    else
       echo $nowPlus $badIP >> $leaseFile
    fi
  fi
done


echo -e 'chain drop_brute {\n    comment "Drop Brute Block Chain"\n' > /tmp/create_drop_brute.nft.tmp

# now parse the leaseFile
while read lease ; do
  leaseTime=`echo $lease|cut -f1 -d\ `
  leaseIP=`echo $lease|cut -f2 -d\ `
  if [ $leaseTime -lt 0 ] ; then
    logLine "Whitelist rule for $leaseIP"
    echo "    ip saddr $leaseIP return" >> /tmp/create_drop_brute.nft.tmp
  elif [ $leaseTime -ge 1 -a $now -gt $leaseTime ] ; then
    logLine "Expiring lease for $leaseIP"
    sed -i /$leaseIP/d $leaseFile
  elif [ $leaseTime -ge 0 ] ; then
    logLine "Drop rule for $leaseIP"
    echo "    ip saddr $leaseIP drop" >> /tmp/create_drop_brute.nft.tmp
  fi
done < $leaseFile

echo -e '}\n' >> /tmp/create_drop_brute.nft.tmp

mv /tmp/create_drop_brute.nft.tmp /tmp/create_drop_brute.nft

[ $alwaysPrintStatus -gt 0 ] && logLine

/etc/init.d/firewall restart
