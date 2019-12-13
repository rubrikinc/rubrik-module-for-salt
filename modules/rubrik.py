# -*- coding: utf-8 -*-
'''
Module for interacting with Rubrik's API

:maintainer:    Tim Hynes <tim.hynes@rubrik.com>
'''

import logging
import sys
import json
import base64
import requests
import salt

sys.path.append('/var/cache/salt/minion/files/extmods/modules/')

requests.packages.urllib3.disable_warnings()
LOG = logging.getLogger(__name__)

def __virtual__():
    return True

def _get_token():
    '''
    Return a token given API credentials provided via pillar
    '''
    try:
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/session'
        b64auth = "Basic "+ base64.b64encode(__salt__['pillar.get']('rubrik.username','')+":"+__salt__['pillar.get']('rubrik.password',''))
        headers = {'Content-Type':'application/json', 'Authorization':b64auth}
        r = requests.post(uri, headers=headers, verify=False)
        if r.status_code == 422:
            raise ValueError("Something went wrong authenticating with the Rubrik cluster")
        token = str(json.loads(r.text)["token"])
        return ("Bearer "+token)
    except:
        LOG.error("Rubrik node connection issues.  Please check Rubrik node IP address or hostname in the YAML configuration file.")

def cluster_info():
    '''
    Return information for the Rubrik cluster
    '''
    try:
        token = _get_token()
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/cluster/me'
        headers = {'Accept':'application/json', 'Authorization':token}
        response = requests.get(uri, headers=headers, verify=False, timeout=15)
        data = response.json()
        my_cluster_info = {
            "id": data['id'],
            "version": data['version'],
            "apiVersion": data['apiVersion']
        }
        return json.dumps(my_cluster_info, sort_keys=True, indent=2, separators=(',', ': '))
    except:
        LOG.error("Something went wrong getting the Rubrik cluster information.")
        return ("Something went wrong getting the Rubrik cluster information.")

def get_vmware_vm_sla(hostname=None):
    '''
    Returns the SLA for the given vSphere VM
    '''
    try:
        if not hostname:
            hostname = __grains__['host']
        token = _get_token()
        '''Check to see if VM exists'''
        my_vm = False
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm?primary_cluster_id=local&is_relic=false&name='+hostname
        headers = {'Accept':'application/json', 'Authorization':token}
        vm_query = requests.get(uri, headers=headers, verify=False, timeout=15)
        for vm in vm_query.json()['data']:
            if vm['name'] == hostname:
                my_vm = vm
        if not my_vm:
            LOG.error("VMware VM not found.")
            return("VMware VM not found")
        return ("Current SLA domain is: "+my_vm['effectiveSlaDomainName'])
    except:
        LOG.error("Something went wrong getting the SLA Domain for this VM.")
        return ("Something went wrong getting the SLA Domain for this VM.")

def set_vmware_vm_sla(hostname=None,sla_domain=None):
    '''
    Updates the SLA for the given vSphere VM
    '''
    try:
        if not hostname:
            hostname = __grains__['host']
        token = _get_token()
        '''Check to see if VM exists'''
        my_vm = False
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm?primary_cluster_id=local&is_relic=false&name='+hostname
        headers = {'Accept':'application/json', 'Authorization':token}
        vm_query = requests.get(uri, headers=headers, verify=False, timeout=15)
        for vm in vm_query.json()['data']:
            if vm['name'] == hostname:
                my_vm = vm
        if not my_vm:
            LOG.error("VMware VM not found.")
            return("VMware VM not found")
        '''Compare current SLA domain to desired one, and update if necessary'''
        if my_vm['effectiveSlaDomainName'] == sla_domain:
            LOG.info('SLA Domain already set to '+sla_domain)
            return ('SLA Domain already set to '+sla_domain)
        else:
            my_sla = False
            uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/sla_domain?primary_cluster_id=local&name='+sla_domain
            headers = {'Accept':'application/json', 'Authorization':token}
            sla_query = requests.get(uri, headers=headers, verify=False, timeout=15)
            for sla in sla_query.json()['data']:
                if sla['name'] == sla_domain:
                    my_sla = sla
            if not my_sla:
                LOG.error("SLA domain not found.")
                return("SLA domain not found")
            uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm/'+my_vm['id']
            headers = {'Content-Type':'application/json','Accept':'application/json','Authorization':token}
            payload = '{"configuredSlaDomainId":"'+my_sla['id']+'"}'
            update_sla = requests.patch(uri, headers=headers, verify=False, data=payload)
            if update_sla.status_code != 200:
                raise ValueError("Something went wrong setting the SLA Domain")
            LOG.info('SLA Domain updated to '+sla_domain)
            return ('SLA Domain updated to '+sla_domain)
    except:
        LOG.error("Something went wrong setting the SLA Domain for this VM.")
        return ("Something went wrong setting the SLA Domain for this VM.")

def od_backup_vmware_vm(hostname=None,sla_domain=None,object_type='vmware_vm'):
    '''
    Takes an on-demand snapshot for the given machine and policy
    '''
    try:
        if not hostname:
            hostname = __grains__['host']
        token = _get_token()
        '''Check to see if VM exists'''
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm?primary_cluster_id=local&is_relic=false&name='+hostname
        headers = {'Accept':'application/json', 'Authorization':token}
        vm_query = requests.get(uri, headers=headers, verify=False, timeout=15)
        for vm in vm_query.json()['data']:
            if vm['name'] == hostname:
                my_vm = vm
        if not my_vm:
            LOG.error("VMware VM not found.")
            return("VMware VM not found")
        '''Figure out the SLA Domain ID'''
        my_sla = False
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/sla_domain?primary_cluster_id=local&name='+sla_domain
        headers = {'Accept':'application/json', 'Authorization':token}
        sla_query = requests.get(uri, headers=headers, verify=False, timeout=15)
        for sla in sla_query.json()['data']:
            if sla['name'] == sla_domain:
                my_sla = sla
        if not my_sla:
            LOG.error("SLA domain not found.")
            return("SLA domain not found")
        '''Take the snapshot'''
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm/'+my_vm['id']+'/snapshot'
        headers = {'Content-Type':'application/json','Accept':'application/json','Authorization':token}
        payload = '{"slaId":"'+my_sla['id']+'"}'
        take_snapshot = requests.post(uri, headers=headers, verify=False, data=payload)
        if take_snapshot.status_code != 202:
            raise ValueError("Something went wrong setting the SLA Domain")
        LOG.info('Snapshot taken')
        return ('Snapshot taken')
    except:
        LOG.error("Something went wrong taking an on-demand snapshot for this VM.")
        return ("Something went wrong taking an on-demand snapshot for this VM.")

def register_host(hostname=None):
    '''
    Registers the host against the Rubrik cluster - requires that the Rubrik Backup Connector be installed,
    and that DNS resolution to the hostname be working correctly (otherwise IP address can be passed using the
    'hostname' parameter)
    '''
    try:
        if not hostname:
            hostname = __grains__['host']
        token = _get_token()
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/host'
        headers = {'Content-Type':'application/json','Accept':'application/json','Authorization':token}
        payload = '{"hostname":"'+hostname+'","hasAgent":true}'
        register_host = requests.post(uri, headers=headers, verify=False, data=payload)
        if register_host.status_code != 201:
            raise ValueError("Something went wrong registering the host")
        LOG.info('Host registered as '+hostname)
        return ('Host registered as '+hostname)
    except:
        LOG.error('Something went wrong registering the host')
        return ('Something went wrong registering the host')
