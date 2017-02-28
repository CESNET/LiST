# What is Security Tools as a Service

Security Tools as a Service (STaaS) is an initiative to provide an easy way to setup and operate network monitoring and analysis toolset provided by CESNET. It takes flow records in form of NetFlow or IPFIX messages and provided tools for reception, processing, storing, analysing and displaying the data and processed results. For complete list of features read ahead to section StaaS components

# STaaS installation

STaaS uses [ansible](https://www.ansible.com/) to automate installation and manage running instances.
The STaaS playbook requires at least version 2.1.0 and is targeted at CentOS 7 and Scientific Linux 7 systems.

## STaaS components

Following Components can be installed using ansible:

- Nemea system including Warden client
- Nemea Dashboard
- Nemea status
- munin with plugins for Nemea
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
differentiate between managed hosts. This configuration can be found 
under the `inventory` directory. IT is possible to have a completely 
separate inventory, for example to track changes in hosts configuration 
 in a repository.

Several variables can be set in the `host_vars/hostname` file:
```
hostname: staas-demo.liberouter.org
timezone: Europe/Prague
scgui_history_minutes: 120
scgui_branch: devel

ansible_become: true
```

Configuration files are located in `host_files/hostname/`
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