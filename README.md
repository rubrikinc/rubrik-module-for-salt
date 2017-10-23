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

* Requires the pyRubrik Python module to be installed
* Requires the following Pillar data to be defined for any nodes using the Rubrik module:

```
rubrik.node: rubrik.demo.com
rubrik.username: admin
rubrik.password: Mypass123!
```
