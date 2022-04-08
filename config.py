#!/usr/bin/env python3
# -*- coding: utf-8 -*-


class Config:
    def __init__(self):
        self.MAIN_DIR: str = '/opt/amnezia_postinstall'
        # full access iptables rules will be created for every ip listed below, place your ip address here
        self.IP_WHITELIST: list = [
            # '1.1.1.1',
            # '8.8.8.8',
        ]
        # comment marker for searching self rules, do not change it!
        self.COMMENT_MARKER: str = 'pi_'
        # comment which will be added to the whitelist iptables rule
        self.WHITELIST_COMMENT: str = 'whitelist_'
        # amnezia containers names starts with
        self.AMNEZIA_CONT_MARKER: str = 'amnezia-'
        # comment for ssh rules
        self.SSH_COMMENT: str = 'ssh_port_'
        # if it True, full access iptables rules will be creating for every current ssh connection
        # BE AWARE! If it False, you can block yourself
        self.CREATE_ACCESS_FOR_CURRENT_SSH_CONN: bool = True
        # comment for iptables rules described above
        self.AUTO_DETECTED_ADMIN_COMMENT: str = 'auto_detected_admin_ip_'
        # save or not iptables rules on reboot
        self.SAVE_V4_RULES_ON_REBOOT: bool = True
        self.SAVE_V6_RULES_ON_REBOOT: bool = True
        self.IPTABLES_RULES_v4: str = '/etc/iptables/rules.v4'
        self.IPTABLES_RULES_v6: str = '/etc/iptables/rules.v6'
        # default iptables policy
        self.V4_INPUT_POLICY: str = 'DROP'
        self.V4_FORWARD_POLICY: str = 'DROP'
        self.V6_INPUT_POLICY: str = 'DROP'
        self.V6_FORWARD_POLICY: str = 'DROP'
        # amnezia docker container ports which never be exposed to internet
        self.NO_EXPOSE_PORTS: list = [
            '3306/tcp',     # mysql tor-website container
            '53/tcp',       # dns-container
            '53/udp',       # dns-container
            '22/tcp',       # sftp-container
        ]
        # restrict access to amnezia services only from countries listed below, no restrictions if empty
        self.AMNEZIA_GEO_RESTRICT: list = [
            # 'ru',
            # 'tm',
            # 'ua',
            # 'sg',
        ]
        # restrict access to ssh only from countries listed below, no access if empty
        self.SSH_GEO_RESTRICT: list = [
            # 'ua',
            # 'sg',
            # 'tm',
        ]
        # ipset systemd unit for save and restore ipset lists after reboot
        self.IPSET_UNIT_NAME: str = "save-ipset-rules.service"
        self.IPSET_UNIT_FILE: str = "/etc/systemd/system/save-ipset-rules.service"
        self.IPSET_LISTS_FILE: str = "/etc/iptables/ipset"
        # recreate ipset countries lists on every script run. make take some time
        self.IPSET_EVERY_RECREATE: bool = False
        self.GEO_URL: str = "http://www.ipdeny.com/ipblocks/data/countries/"
        self.TMP_DIR: str = '/tmp'
        # cron job for periodically update ipset countries lists
        self.CREATE_IPSET_CRON_SCHEDULE: bool = True
        self.CRON_FILE: str = '/etc/cron.d/update-ipset-country-lists'
        self.CRON_IPSET_UPDATE_INTERVAl: int = 30  # days
        # rc.local - autorun systemd unit. using for check iptables rules after system reboot
        self.RC_LOCAL_FILE: str = "/etc/rc.local"
        self.RC_LOCAL_UNIT_NAME: str = "rc-local.service"
        self.RC_LOCAL_UNIT_FILE: str = "/etc/systemd/system/rc-local.service"
        # script execution timeout after system boot (seconds)
        self.RC_LOCAL_RUN_TIMEOUT: int = 3
        # docker
        # disable docker containers json log for privacy and performance
        self.DISABLE_DOCKER_JSON_LOG: bool = False
        self.DOCKER_CONT_PATH: str = '/var/lib/docker/containers'
        self.DOCKER_HOSTCONF_FILE: str = 'hostconfig.json'
        # dns. Placing static dns records from dns_hosts file to amnezia-dns container a-records.conf
        self.DNS_USER_RECORDS: bool = False
        self.DNS_CONT_NAME: str = 'amnezia-dns'
        self.DNS_HOSTS_FILE: str = "dns_hosts"
        self.DNS_CONT_A_FILE: str = "/opt/unbound/etc/unbound/a-records.conf"
        # logger
        self.LOG_LEVEL: str = "INFO"
        self.LOG_FILE: str = "amnezia_postinstall.log"
        self.LOG_FILE_SIZE: int = 500000
        self.LOG_ROTATE_COUNT: int = 2
        self.LOG_TO_FILE: bool = False
        self.LOG_TO_CONSOLE: bool = True
        # additional packages to install
        self.MISC_PACKAGES: list = [
            # 'ccze',
            # 'vim',
            # 'tmux',
            'htop',
            'iotop',
            # 'mc',
            'ntpdate',
        ]
        # github
        self.GIT_USER: str = 'your_github_username'
        self.GIT_PASSWORD: str = 'not_used'
        self.GIT_TOKEN: str = 'your_github_token'
        # cloning .bashrc from your repo to vps
        self.CLONE_BASHRC: bool = False
        self.BASHRC_HTTP_REPO: str = 'https://github.com/PATH_TO_YOUR_REPO.git'
        # cloning .vimrc from your repo to vps
        self.CLONE_VIMRC: bool = False
        self.VIMRC_HTTP_REPO: str = 'https://github.com/PATH_TO_YOUR_REPO.git'
        # cloning tmux.conf from your repo to vps
        self.CLONE_TMUX_CONF: bool = False
        # repo must contain tmux2.conf and tmux3.conf for tmux version 2 and 3
        self.TMUX_CONF_REPO: str = 'https://github.com/PATH_TO_YOUR_REPO.git'
        # tmux plugin manager repo
        self.TMUX_TPM_PLUG_REPO: str = 'https://github.com/tmux-plugins/tpm'
        self.TMUX_TPM_PLUG_DIR: str = '~/.tmux/plugins/tpm'
        # trafshow monitor purge interval
        self.TRAFSHOW_PURGE_INTERVAL: int = 4

