# Rubrik Salt Module

## Overview

Rubrik module for the Salt configuration management tool.

Features the following resources:

* Cluster Info
* Get SLA Domain
* Set SLA Domain
* On-Demand Snapshot
* Register host with Rubrik cluster
* Install Rubrik Connector Service

## Pre-requisites

* Requires the following Pillar data to be defined for any nodes using the Rubrik module:

```
rubrik.node: rubrik.demo.com
rubrik.username: admin
rubrik.password: Mypass123!
```

* Module should be copied to the `_modules` folder on the Salt master, and distributed to the hosts using the `salt '*' saltutil.sync_all` command

## Functions

### cluster_info

Returns information about the cluster, this is used as a test to make sure connectivity to the cluster is good.

#### Example Usage

```none
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.cluster_info -v
Executing job with jid 20171024100133454853
-------------------------------------------

th-salt-minion01.rangers.lab:
    {
      "apiVersion": "1",
      "id": "89fc0d86-6f1c-4652-aefa-37b7ba0e6229",
      "version": "4.0.3-474"
    }
```

### get_vmware_vm_sla

Returns the SLA domain for the given host. Parameter `hostname` can be used to pass a different hostname if required, otherwise this will use the minion's grains to pull the hostname.

#### Example Usage

```none
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.get_vmware_vm_sla hostname='foobar'
th-salt-minion01.rangers.lab:
    VMware VM not found
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.get_vmware_vm_sla
th-salt-minion01.rangers.lab:
    Current SLA domain is: Gold
```

### set_vmware_vm_sla

Sets the SLA domain to the value named in `sla_domain`. Parameter `hostname` can be used to pass a different hostname if required, otherwise this will use the minion's grains to pull the hostname.

#### Example Usage

```none
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.set_vmware_vm_sla sla_domain='Silver' -v
Executing job with jid 20171024121337392104
-------------------------------------------

th-salt-minion01.rangers.lab:
    SLA Domain already set to Silver
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.set_vmware_vm_sla sla_domain='Bronze' -v
Executing job with jid 20171024121343410581
-------------------------------------------

th-salt-minion01.rangers.lab:
    SLA Domain updated to Bronze
```

### od_backup_vmware_vm

Takes an on-demand snapshot of the target machine. Parameter `hostname` can be used to pass a different hostname, as well as `sla_domain` to specify the SLA domain to attach to the snapshot.

#### Example Usage

```none
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.od_backup_vmware_vm
th-salt-minion01.rangers.lab:
    Snapshot taken
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.od_backup_vmware_vm sla_domain='Silver'
th-salt-minion01.rangers.lab:
    Snapshot taken
```

### register_host

Registers the target host with the Rubrik cluster. This requires that the Rubrik Backup Connector be installed, running, and accessible on the target system, and that DNS resolution from the Rubrik cluster be working correctly. The `hostname` parameter can be passed as shown in the examples below to pass the IP of the host, if DNS resolution will not be possible.

#### Example Usage

```none
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.register_host
th-salt-minion01.rangers.lab:
    Something went wrong registering the host
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.register_host hostname='th-mongo-01'
th-salt-minion01.rangers.lab:
    Something went wrong registering the host
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.register_host hostname='172.21.11.119'
th-salt-minion01.rangers.lab:
    Host registered as 172.21.11.119
```