# What is Security Tools as a Service

Security Tools as a Service (STaaS) is an initiative to provide an easy way to setup and operate network monitoring and analysis toolset provided by CESNET. It takes flow records in form of NetFlow or IPFIX messages and provided tools for reception, processing, storing, analysing and displaying the data and processed results. For complete list of features read ahead to section StaaS components

# STaaS installation

STaaS uses [ansible](https://www.ansible.com/) to automate installation and manage running instances.
The STaaS playbook requires at least version 2.1.0 and is targeted at CentOS 7 and Scientific Linux 7 systems.

## STaaS components

Following Components can be installed using ansible:

- [NEMEA system](https://github.com/CESNET/nemea) including [Warden client](https://warden.cesnet.cz)
- [NEMEA Dashboard](https://github.com/CESNET/nemea-dashboard)
- NEMEA status
- munin with plugins for NEMEA
- [SecurityCloud GUI](https://github.com/CESNET/SecurityCloudGUI)
- [Liberouter GUI](https://github.com/CESNET/Liberouter-GUI)
- [IPFIXcol](https://github.com/CESNET/ipfixcol)

Optional:

- [Nagios](https://nagios.org) monitoring
- Local Warden server for testing
- Local Warden client that writes to files
- [Let's Encrypt](https://letsencrypt.org/) certificate

## STaaS server initial configuration

To install STaaS on a new server, the ansible has to have access to a root or a user with sudo.
Following configuration is also expected:

`/etc/sysconfig/iptables`

```
-A INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 5555 -j ACCEPT
-A INPUT -p tcp -m state --state NEW -m tcp --dport 5666 -j ACCEPT
-A INPUT -p udp --dport 4739 -j ACCEPT
```

To permit ports: 80/TCP (Webserver), 443/TCP (Webserver), 5555/TCP (NEMEA Dashboard backend), 5666/TCP (NRPE - Nagios), 4739/UDP (IPFIXcol).

`/etc/sudoers`

```
Defaults   !requiretty
```

`/etc/sysconfig/selinux`

```
SELINUX=permissive
```

## STaaS inventory file

Each hosts file can specify following host groups:

- `[staas]` - Basic STaaS provisioning
- `[warden]` - Local Warden server installation for testing
- `[letsencrypt]` - Create Let's encrypt certificate for the hosts, needs public IP
- `[nagios-clients]` - Clients to be monitored by Nagios server
- `[nagios-servers]` - Nagios server to monitor the clients

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
sample_data_src: "http://www.liberouter.org/~thorgrin/data.ipfix.bz2"
mongod_cachesizeGB: 1
nagios_client_hostgroups: [nemea-collectors, staas]
nagios_client_contacts: []
nagios_client_exclude_services: [nemea-running-modules, link-traffic]
nagios_server_nopasswd: false

letsencrypt_cert: {
    email: "staas@cesnet.cz"
}

ansible_become: true
```

The sample data URL should point to bzipped2 ipfix file with data 
stored by ipfix plugin of IPFIXcol collector.

Size of Mongo database cache in gigabytes. Allows float numbers (e.g.: 0.25)

Nagios client hostgroup list is a list of hostgroups to which the host
belongs. If it is not an existing (nemea-collectors or staas), the hostgroup must
be created by adding configuration file for it (see next lines). Default is both `nemea-collectors` and `staas` hostgroups.

Each host monitored by nagios can report to specific contacts. If none are specified, notifications are sent to `admins` contact group. The contacts must already exist.

Nagios client can be excluded from specific services if necessary.

Nagios server can be installed without password (for demo or secure environment).

Let's encrypt certificate creation allows to set custom contact mail.

Configuration files are located in `host_files/hostname/`:

- `nemea` directory copies to /etc/nemea
- `warden` directory copies to /etc/warden and contains configuration for warden client
- `certificate` directory must contain `certificate.crt` and `certificate.key` files that are used for apache and nemea-dashboard API
- `ipfixcol` directory can contain:
  - `ipfixcol-startup.xml`, which is the base to which other configuration parts are added.
  - `profiles.xml`, which is used to configure profiles by the SecurityCloud GUI
- `nagios` directory for configuring Nagios service
  - `server` directory contents is copied to /etc/nagios/conf.d and 
  can be used to define new hostgroups and services.

## Usage of Ansible

The ansible playbook uses two main tags: `install` and `update`. At least one of them has to be given at any time. The `install` tag is for initial installation, the `update` skips some steps that do not need to be repeated and refreshes repository caches so that latest versions of packages are installed.

To select only part of the playbook, `--skip-tags` can be used with ansible-playbook. Almost all roles can be excluded, list all tags that are to be applied by `--list-tags`

A basic ansible playbook command (call from the `ansible` directory):
```
ansible-playbook -i inventory/hosts site.yml --tags install
```

The `site.yml` playbook includes all parts of the STaaS. You can use only selected playbooks, e.g. `nagios.yml` to setup nagios. In that case, everything except Nagios roles and hostgroups are ignored.

## STaaS Vagrant box

Local development and testing of STaaS can be easily done using Vagrant box. Just go to vagrant directory and call

```
vagrant up
```

It will create new virtual machine and automatically apply the STaaS ansible playbook. 

## Default login

- Nemea-Dashboard: nemea/nemea
- Liberouter GUI: admin/admin
