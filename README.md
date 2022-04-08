# amnezia_postinstall

This is NOT part of [amnezia-vpn](https://github.com/amnezia-vpn) project

Script for configuring your vps after amnezia-vpn containers installed.
 
- setting iptables policy
- checking iptables rules
- restrict access to container service by geo ipset list
- creating rc.local autorun systemd unit
- creating cron file for periodically update ipset lists
- switching off containers json-logging
- adding your own static dns A records to amnezia-dns container
- cloning .bashrc, .vimrc, tmux.conf from your repository
- adaptive monitoring connections to containers in real time (trafshow) 

## Requirements
- python3
- amnezia-vpn v.2.0.8

## OS support
 - Ubuntu 18,20
 - Debian 10,11
 
## Some warnings
- install any amnezia container before running this script
- run as root
- it is not recommended to run on vps behind the nat (Such as Amazon, Oracle etc) 

## Installation

```bash
apt update
apt install git
git clone https://github.com/diss0lver/amnezia_postinstall.git /opt/amnezia_postinstall
```

## Usage
Edit config.py with your favorite editor. Make script executable. Run.  

```bash
cd /opt/amnezia_postinstall
nano config.py
chmod +x amnezia_postinstall.py
chmod +x monitor.py
./amnezia_postinstall.py
./monitor.py
```

## License
[MIT](https://choosealicense.com/licenses/mit/)
