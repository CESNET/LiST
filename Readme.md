# STaaS Installation

STaaS uses [ansible](https://www.ansible.com/) to automate installation and manage running instances.
The STaaS playbook requires at least version 2.1.0 and is targeted at CentOS 7 and Scientific Linux 7 systems.

## STaaS components

Following Components can be installed using ansible:

- Nemea system
- Nemea Dashboard
- Nemea status
- munin
- SecurityCloud GUI

Optional:

- Local Warden server for testing
- Local Warden client that writes to files
- Let's Encrypt certificate

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

## STaaS per host configuration

It is possible to specify per host variables and configuration file to 
differentiate between managed hosts.

Several variables can be set in the `host_vars/hostname` file:
```
hostname: staas-demo.liberouter.org
timezone: Europe/Prague
ansible_become: true
```

Configuration files are located in `files/hostname/`
- `nemea` directory copies to /etc/nemea
- `warden` directory copies to /etc/warden and contains configuration for warden client
- `certificate` directory must contain `certificate.crt` and `certificate.key` files that are used for apache and nemea-dashboard API
- `ipfixcol` directory can contain:
  - `ipfixcol-startup.xml`, which is the base to which other configuration parts are added.
  - `profiles.xml`, which is used to configure profiles by the SecurityCloud GUI

## STaaS Vagrant box

Local development and testing of STaaS can be easily done using Vagrant box. Just go to vagrant directory and call
```
vagrant up
```

It will create new virtual machine and automatically apply the STaaS ansible playbook. 