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

* Requires the pyRubrik Python module to be installed on each minion (will later add this as a state):
1. Clone repo to destination host
1. cd to `module-utils/RubrikLib`, run `sudo -H python setup.py install`
1. cd to `module-utils/RubrikLib_Int`, run `sudo -H python setup.py install`
* Requires the following Pillar data to be defined for any nodes using the Rubrik module:

```
rubrik.node: rubrik.demo.com
rubrik.username: admin
rubrik.password: Mypass123!
```

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

### get_sla

Returns the SLA domain for the given host. Parameter `hostname` can be used to pass a different hostname if required, otherwise this will use the minion's grains to pull the hostname.

#### Example Usage

```none
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.get_sla hostname='foobar'
th-salt-minion01.rangers.lab:
    VMware VM not found
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.get_sla
th-salt-minion01.rangers.lab:
    Current SLA domain is: Gold
```

### set_sla

Sets the SLA domain to the value named in `sla_domain`. Parameter `hostname` can be used to pass a different hostname if required, otherwise this will use the minion's grains to pull the hostname.

#### Example Usage

```none
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.set_sla sla_domain='Silver' -v
Executing job with jid 20171024121337392104
-------------------------------------------

th-salt-minion01.rangers.lab:
    SLA Domain already set to Silver
root@th-salt-master:/srv/salt/_modules# salt '*' rubrik.set_sla sla_domain='Bronze' -v
Executing job with jid 20171024121343410581
-------------------------------------------

th-salt-minion01.rangers.lab:
    SLA Domain updated to Bronze
```