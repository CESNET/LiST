# STaaS Installation

STaaS uses [ansible](https://www.ansible.com/) to automate installation and manage running instances.
The STaaS playbook requires at least version 2.1.0 and is targeted at CentOS 7 and Scientific Linux 7 systems.

## STaaS components

Following Components can be installed using ansible:

- Nemea system
- Nemea Dashboard
- Nemea status
- munin

Optional:

- Local Warden server for testing

## STaaS server initial configuration

To install STaaS on a new server, the ansible has to have access to a root or a user with sudo.
Following configuration is also expected:

/etc/sysconfig/iptables
```
-A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 5555 -j ACCEPT
ports 80, 443, 5555
```

/etc/sudoers
```
Defaults   !requiretty
```

/etc/sysconfig/selinux
```
SELINUX=permissive
```

## STaaS Vagrant box

Local development and testing of STaaS can be easily done using Vagrant box. Just go to vagrant directory and call
```
vagrant up
```

It will create new virtual machine and automatically apply the STaaS ansible playbook. 