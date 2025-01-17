# dropBrute

## I am still trying to maintain this. Please report any issues. I will make best effort.

**Lightweight fail2ban alternative for OpenWRT**

Runs via cron; inspects ssh log for brute force attacks and blocks via 
fw4.  Includes whitelist and blacklist support, and openssh-server support.

Initial version posted 10/31/2011 at https://forum.openwrt.org/viewtopic.php?pid=224122

Updated for OpenWrt 22.03 using fw4 / netfilter (**Will not work with fw3 or iptables, or OpenWrt versions before 22.03**)

### Installation Instructions

These installation instructions can be cut and paste into the terminal

Retrieve the latest copy of dropBrute.sh from gitHub

	DB=/usr/sbin/dropBrute.sh
	curl -ko $DB https://raw.github.com/bryandhill/dropBrute/master/dropBrute.sh
	chmod 755 $DB

Optionally edit the variables in the header of this script to customise

	vi $DB

Setup fw4 "hook" scripts:

	mkdir -p /usr/share/nftables.d/table-post/
	mkdir -p /usr/share/nftables.d/chain-pre/input_wan/
	echo 'jump drop_brute' > /usr/share/nftables.d/chain-pre/input_wan/inject_jump_drop_brute.nft
	echo -e 'chain drop_brute {\n    comment "Drop Brute Block Chain"\n}\n' > /tmp/create_drop_brute.nft
	ln -s /tmp/create_drop_brute.nft /usr/share/nftables.d/table-post/create_drop_brute.nft

Run the script periodically out of cron:

	echo '*/10 * * * * /usr/sbin/dropBrute.sh 2>&1 >> /tmp/dropBrute.log' >> /etc/crontabs/root

If cron is not enabled, you'll also need to run the following:

	/etc/init.d/cron enable && /etc/init.d/cron start

Setup any permanent blacklist/whitelist entries.  The script by default will whitelist your local network, edit the script header to disable this functionality.  To whitelist hosts or networks, simply add a manual entry to the lease file with a leasetime of -1.  This can be done with the following syntax:

	echo -1 192.168.1.0/24 >> /tmp/dropBrute.leases

A static, or non-expiring blacklist of a host or network can also be added, just use a lease time of 0.  This can be done with the following syntax:

	echo 0 1.2.3.0/24 >> /tmp/dropBrute.leases
