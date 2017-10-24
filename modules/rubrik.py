# -*- coding: utf-8 -*-
'''
Module for interacting with Rubrik's API

:maintainer:    Tim Hynes <tim.hynes@rubrik.com>
:depends:       pyRubrik Python module
                requests Python module
'''

import logging
import sys
import json
import requests
import salt

sys.path.append('/var/cache/salt/minion/files/extmods/modules/')

requests.packages.urllib3.disable_warnings()
log = logging.getLogger(__name__)

try:
    import pyRubrik as RubrikClient
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

def __virtual__():
    if not HAS_DEPS:
        return False
    return 'rubrik'

def _rubrik_obj():
    '''
    Return a new Rubrik object given API credentials provided via pillar
    '''
    try:
        return RubrikClient.create(__salt__['pillar.get']('rubrik.node',''),__salt__['pillar.get']('rubrik.username',''),__salt__['pillar.get']('rubrik.password',''))
    except:
        log.error("Rubrik node connection issues.  Please check Rubrik node IP address or hostname in the YAML configuration file.")

def cluster_info():
    '''
    Return information for the Rubrik cluster
    '''
    try:
        rk = _rubrik_obj()
        my_cluster_info = {
            "id": rk.get_public_cluster_info().id,
            "version": rk.get_public_cluster_info().version,
            "apiVersion": rk.get_public_cluster_info().api_version
        }
        return json.dumps(my_cluster_info, sort_keys=True, indent=2, separators=(',', ': '))
    except:
        log.error("Something went wrong getting the Rubrik cluster information.")

def get_sla(hostname=None):
    '''
    Returns the SLA for the given machine
    '''
    if not hostname:
        hostname = __grains__['host']
    rk = _rubrik_obj()

    '''Check to see if VM exists'''
    my_vm = False
    vm_query = rk.query_vm(primary_cluster_id='local', limit=20000, is_relic=False, name=hostname)
    for vm in vm_query.data:
        if vm.name == hostname:
            my_vm = vm

    if not my_vm:
        log.error("VMware VM not found.")
        return("VMware VM not found")

    return ("Current SLA domain is: "+my_vm.effective_sla_domain_name)

def set_sla(hostname=None,sla_domain=None):
    '''
    Updates the SLA for the given machine
    '''
    if not hostname:
        hostname = __grains__['host']
    rk = _rubrik_obj()

    '''Check to see if VM exists'''
    my_vm = False
    vm_query = rk.query_vm(primary_cluster_id='local', limit=20000, is_relic=False, name=hostname)
    for vm in vm_query.data:
        if vm.name == hostname:
            my_vm = vm

    if not my_vm:
        log.error("VMware VM not found.")
        return("VMware VM not found")

    '''Compare current SLA domain to desired one, and update if necessary'''
    if my_vm.effective_sla_domain_name == sla_domain:
        log.info('SLA Domain already set to '+sla_domain)
        return ('SLA Domain already set to '+sla_domain)
    else:
        my_sla = False
        sla_query = rk.query_sla_domain(primary_cluster_id='local', limit=20000, is_relic=False, name=sla_domain)
        for sla in sla_query.data:
            if sla.name == sla_domain:
                my_sla = sla

        if not my_sla:
            log.error("SLA domain not found.")
            return("SLA domain not found")

        rk.update_vm(id=my_vm.id, vm_update_properties={"configured_sla_domain_id": my_sla.id})
        log.info('SLA Domain updated to '+sla_domain)
        return ('SLA Domain updated to '+sla_domain)

def od_backup(hostname=None,sla_domain=None,object_type='vmware_vm'):
    '''
    Takes an on-demand snapshot for the given machine and policy
    '''
    if not hostname:
        hostname = __grains__['host']
    rk = _rubrik_obj()
    ''' Check to see if object type exists'''
    object_exists = False
    object_types = ['vmware_vm']
    object_exists = object_type in object_types
    if not object_exists:
        log.info("Object type " + object_type + " does not exist.  Please check the input attributes.")
        return("Object type " + object_type + " does not exist.  Please check the input attributes.")

    '''Check to see if VM exists'''
    my_vm = False
    vm_query = rk.query_vm(primary_cluster_id='local', limit=20000, is_relic=False, name=hostname)
    for vm in vm_query.data:
        if vm.name == hostname:
            my_vm = vm

    if not my_vm:
        log.error("VMware VM not found.")
        return("VMware VM not found")

    '''Figure out the SLA Domain ID'''
    my_sla = False
    if sla_domain:
        my_sla_name = sla_domain
    else:
        my_sla_name = my_vm.effective_sla_domain_name
    sla_query = rk.query_sla_domain(primary_cluster_id='local', limit=20000, is_relic=False, name=my_sla_name)
    for sla in sla_query.data:
        if sla.name == my_sla_name:
            my_sla = sla

    if not my_sla:
            log.error("SLA domain not found.")
            return("SLA domain not found")

    '''Take the snapshot'''
    rk.create_on_demand_backup(id=my_vm.id,config={"sla_id": my_sla.id})
    log.info('Snapshot taken')
    return ('Snapshot taken')

def register_host(hostname=None):
    '''
    Registers the host against the Rubrik cluster - requires that the Rubrik Backup Connector be installed,
    and that DNS resolution to the hostname be working correctly (otherwise IP address can be passed using the
    'hostname' parameter)
    '''
    if not hostname:
        hostname = __grains__['host']
    rk = _rubrik_obj()
    try:
        rk.register_host(host={"hostname": hostname, "hasAgent":True})
        log.info('Host registered as '+hostname)
        return ('Host registered as '+hostname)
    except:
        log.error('Something went wrong registering the host')
        return ('Something went wrong registering the host')
