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
    Returns the SLA for the current machine
    '''
    aliases = []
    if not hostname:
        hostname = __grains__['host']
    '''
    else:

        aliases.append(__grains__['host'])
        for ip_address in __grains__['ipv4']:
            if not ip_address == '127.0.0.1':
                aliases.append(ip_address)
    '''
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