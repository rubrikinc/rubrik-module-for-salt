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
    except Exception,e:
        exc_tuple = sys.exc_info()
        LOG.error("Rubrik node connection issues.  Please check Rubrik node IP address or hostname in the YAML configuration file, error: "+str(e))
        return ("Rubrik node connection issues.  Please check Rubrik node IP address or hostname in the YAML configuration file, error: "+str(e))

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
    except Exception,e:
        exc_tuple = sys.exc_info()
        LOG.error("Something went wrong getting the Rubrik cluster information, error: "+str(e))
        return ("Something went wrong getting the Rubrik cluster information, error: "+str(e))

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
            raise ValueError("VMware VM not found")
        return ("Current SLA domain is: "+my_vm['effectiveSlaDomainName'])
    except Exception,e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong getting the SLA Domain for this VM, error: '+str(e))
        return ('Something went wrong getting the SLA Domain for this VM, error: '+str(e))

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
            raise ValueError("VMware VM not found")
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
                raise ValueError("SLA domain not found")
            uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm/'+my_vm['id']
            headers = {'Content-Type':'application/json','Accept':'application/json','Authorization':token}
            payload = '{"configuredSlaDomainId":"'+my_sla['id']+'"}'
            update_sla = requests.patch(uri, headers=headers, verify=False, data=payload)
            if update_sla.status_code != 200:
                raise ValueError("Something went wrong setting the SLA Domain")
            LOG.info('SLA Domain updated to '+sla_domain)
            return ('SLA Domain updated to '+sla_domain)
    except Exception,e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong setting the SLA Domain for this VM, error: '+str(e))
        return ('Something went wrong setting the SLA Domain for this VM, error: '+str(e))

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
            raise ValueError("VMware VM not found")
        '''Figure out the SLA Domain ID'''
        my_sla = False
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/sla_domain?primary_cluster_id=local&name='+sla_domain
        sla_query = requests.get(uri, headers=headers, verify=False, timeout=15)
        for sla in sla_query.json()['data']:
            if sla['name'] == sla_domain:
                my_sla = sla
        if not my_sla:
            LOG.error("SLA domain not found.")
            raise ValueError("SLA domain not found")
        '''Take the snapshot'''
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm/'+my_vm['id']+'/snapshot'
        headers = {'Content-Type':'application/json','Accept':'application/json','Authorization':token}
        payload = '{"slaId":"'+my_sla['id']+'"}'
        take_snapshot = requests.post(uri, headers=headers, verify=False, data=payload)
        if take_snapshot.status_code != 202:
            raise ValueError("Something went wrong setting the SLA Domain")
        LOG.info('Snapshot taken')
        return ('Snapshot taken')
    except Exception,e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong taking an on-demand snapshot for this VM, error: '+str(e))
        return ('Something went wrong taking an on-demand snapshot for this VM, error: '+str(e))

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
        data = register_host.json()
        message = 'Host registered as '+hostname+', host ID is '+data['id']
        LOG.info(message)
        return message
    except Exception,e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong registering the host, error: '+str(e))
        return ('Something went wrong registering the host, error: '+str(e))

def add_fileset_to_host(hostname=None,fileset_name=None,sla_domain=None,os_type='Linux'):
    '''
    Adds a fileset to a Windows/Linux/Unix host
    '''
    try:
        if not hostname:
            hostname = __grains__['host']
        token = _get_token()
        if os_type == 'Linux':
            os_type = 'UnixLike'
        elif os_type == 'Windows':
            os_type = 'Windows'
        '''Figure out the Host ID'''
        my_host = False
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/host?primary_cluster_id=local&operating_system_type='+os_type+'&name='+hostname
        headers = {'Accept':'application/json', 'Authorization':token}
        host_query = requests.get(uri, headers=headers, verify=False, timeout=15)
        for host in host_query.json()['data']:
            if host['name'] == hostname:
                my_host = host
        if not my_host:
            LOG.error("Host not found.")
            raise ValueError("Host not found")
        '''Figure out the Fileset Template ID'''
        my_fst = False
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/fileset_template?primary_cluster_id=local&operating_system_type='+os_type+'&name='+fileset_name
        fst_query = requests.get(uri, headers=headers, verify=False, timeout=15)
        for fst in fst_query.json()['data']:
            if fst['name'] == fileset_name:
                my_fst = fst
        if not my_fst:
            LOG.error("Fileset template not found.")
            raise ValueError("Fileset template not found")
        '''Figure out the SLA Domain ID'''
        my_sla = False
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/sla_domain?primary_cluster_id=local&name='+sla_domain
        sla_query = requests.get(uri, headers=headers, verify=False, timeout=15)
        for sla in sla_query.json()['data']:
            if sla['name'] == sla_domain:
                my_sla = sla
        if not my_sla:
            LOG.error("SLA domain not found.")
            raise ValueError("SLA domain not found")
        '''Check if fileset already exists'''
        fileset_id = False
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/fileset?primary_cluster_id=local&is_relic=false&host_id='+my_host['id']+'&template_id='+my_fst['id']
        fileset_query = requests.get(uri, headers=headers, verify=False, timeout=15)
        if fileset_query.json()['total'] >= 0:
            fileset_id = fileset_query.json()['data'][0]['id']
        '''Create fileset'''
        if not fileset_id:
            uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/fileset'
            headers = {'Content-Type':'application/json','Accept':'application/json','Authorization':token}
            payload = '{"hostId":"'+my_host['id']+'","templateId":"'+my_fst['id']+'"}'
            create_fileset = requests.post(uri, headers=headers, verify=False, data=payload)
            if create_fileset.status_code != 201:
                raise ValueError("Something went wrong creating the fileset")
            data = create_fileset.json()
            fileset_id = data['id']
        '''Assign SLA'''
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/fileset/'+fileset_id
        headers = {'Content-Type':'application/json','Accept':'application/json','Authorization':token}
        payload = '{"configuredSlaDomainId":"'+my_sla['id']+'"}'
        register_host = requests.patch(uri, headers=headers, verify=False, data=payload)
        if register_host.status_code != 200:
            raise ValueError("Something went wrong applying the SLA to the fileset")
        data = register_host.json()
        message = 'Fileset created, ID is '+fileset_id+'. SLA '+my_sla['name']+' applied.'
        LOG.info(message)
        return message
    except Exception,e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong creating the fileset, error: '+str(e))
        return ('Something went wrong creating the fileset, error: '+str(e))