# -*- coding: utf-8 -*-
'''
Module for interacting with Rubrik's API

:maintainer:    Tim Hynes <tim.hynes@rubrik.com>
'''

import time
import logging
import sys
import json
import base64
import requests
import salt
import datetime

sys.path.append('/var/cache/salt/minion/files/extmods/modules/')

requests.packages.urllib3.disable_warnings()
LOG = logging.getLogger(__name__)

def __virtual__():
    return True

def _get_auth_header():
    if sys.version_info < (3,):
        return base64.b64encode(__salt__['pillar.get']('rubrik.username','')+":"+__salt__['pillar.get']('rubrik.password',''))
    else:
        return base64.b64encode(bytes(__salt__['pillar.get']('rubrik.username','')+':'+__salt__['pillar.get']('rubrik.password',''),'utf-8'))

def _get_token():
    '''
    Return a token given API credentials provided via pillar
    '''
    try:
        uri = ('https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/session')
        b64auth = 'Basic {0}'.format(_get_auth_header().decode("utf-8"))
        headers = {'Content-Type':'application/json', 'Authorization':b64auth}
        r = requests.post(uri, headers=headers, verify=False)
        if r.status_code == 422:
            raise ValueError("Something went wrong authenticating with the Rubrik cluster")
        token = str(json.loads(r.text)["token"])
        return ('Bearer {0}'.format(token))
    except Exception as e:
        exc_tuple = sys.exc_info()
        LOG.error("Rubrik node connection issues.  Please check Rubrik node IP address or hostname in the YAML configuration file, error: "+str(e))
        return ("Rubrik node connection issues.  Please check Rubrik node IP address or hostname in the YAML configuration file, error: "+str(e))

def cluster_info():
    '''
    Return information for the Rubrik cluster
    '''
    try:
        token = _get_token()
        uri = ('https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/cluster/me')
        headers = {'Accept':'application/json', 'Authorization':token}
        response = requests.get(uri, headers=headers, verify=False, timeout=15)
        data = response.json()
        my_cluster_info = {
            "id": data['id'],
            "version": data['version'],
            "apiVersion": data['apiVersion']
        }
        return json.dumps(my_cluster_info, sort_keys=True, indent=2, separators=(',', ': '))
    except Exception as e:
        exc_tuple = sys.exc_info()
        LOG.error("Something went wrong getting the Rubrik cluster information, error: "+str(e))
        return ("Something went wrong getting the Rubrik cluster information, error: "+str(e))

def get_vmware_vm_sla(hostname=None):
    '''
    Returns the SLA for the given vSphere VM
    '''
    try:
        if not hostname:
            hostname = __grains__['id']
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
    except Exception as e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong getting the SLA Domain for this VM, error: '+str(e))
        return ('Something went wrong getting the SLA Domain for this VM, error: '+str(e))

def set_vmware_vm_sla(hostname=None,sla_domain=None):
    '''
    Updates the SLA for the given vSphere VM
    '''
    try:
        if not hostname:
            hostname = __grains__['id']
        if not sla_domain:
            LOG.error("No SLA Domain name passed")
            raise ValueError("No SLA Domain name passed")
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
    except Exception as e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong setting the SLA Domain for this VM, error: '+str(e))
        return ('Something went wrong setting the SLA Domain for this VM, error: '+str(e))

def od_backup_vmware_vm(hostname=None,sla_domain=None,object_type='vmware_vm',wait_for_completion=False):
    '''
    Takes an on-demand snapshot for the given machine and policy
    '''
    try:
        if not hostname:
            hostname = __grains__['id']
        if not sla_domain:
            LOG.error("No SLA Domain name passed")
            raise ValueError("No SLA Domain name passed")
        token = _get_token()
        '''Check to see if VM exists'''
        uri = ('https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm?primary_cluster_id=local&is_relic=false&name='+hostname)
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
        uri = ('https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/sla_domain?primary_cluster_id=local&name='+sla_domain)
        sla_query = requests.get(uri, headers=headers, verify=False, timeout=15)
        for sla in sla_query.json()['data']:
            if sla['name'] == sla_domain:
                my_sla = sla
        if not my_sla:
            LOG.error("SLA domain not found.")
            raise ValueError("SLA domain not found")
        '''Take the snapshot'''
        uri = ('https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm/'+my_vm['id']+'/snapshot')
        headers = {'Content-Type':'application/json','Accept':'application/json','Authorization':token}
        payload = '{"slaId":"'+my_sla['id']+'"}'
        take_snapshot = requests.post(uri, headers=headers, verify=False, data=payload)
        if take_snapshot.status_code != 202:
            raise ValueError("Something went wrong setting the SLA Domain")
        task_id = take_snapshot.json()["id"]
        LOG.info('Snapshot taken with task ID: '+task_id)
        if wait_for_completion:
            status = take_snapshot.json()["status"]
            while status not in ['SUCCEEDED','FAILED','WARNING']:
                time.sleep(5)
                uri = ('https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm/request/'+task_id)
                task_status = requests.get(uri, headers=headers, verify=False)
                status = task_status.json()["status"]
            LOG.info('Snapshot finished with status: '+status)
            return ('Snapshot finished with status: '+status)
        else:
            return ('Snapshot taken with task ID: '+task_id)
    except Exception as e:
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
            hostname = __grains__['id']
        token = _get_token()
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/host'
        headers = {'Content-Type':'application/json','Accept':'application/json','Authorization':token}
        payload = '{"hostname":"'+hostname+'","hasAgent":true}'
        register_host = requests.post(uri, headers=headers, verify=False, data=payload)
        if register_host.status_code != 201:
            raise ValueError("Status code: "+str(register_host.status_code)+", message: "+register_host.json()["message"])
        data = register_host.json()
        message = 'Host registered as '+hostname+', host ID is '+data['id']
        LOG.info(message)
        return message
    except Exception as e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong registering the host, error: '+str(e))
        return ('Something went wrong registering the host, error: '+str(e))

def get_host_registration(hostname=None,os_type='Linux'):
    '''
    Checks the host registration status, returning a boolean value (true=registered, false=not_registered)
    '''
    try:
        host_registered = False
        if not hostname:
            hostname = __grains__['id']
        token = _get_token()
        if os_type == 'Linux':
            os_type = 'UnixLike'
        elif os_type == 'Windows':
            os_type = 'Windows'
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/host?primary_cluster_id=local&operating_system_type='+os_type+'&name='+hostname
        headers = {'Accept':'application/json', 'Authorization':token}
        host_query = requests.get(uri, headers=headers, verify=False, timeout=15)
        if host_query.json()['total'] == 0:
            host_registered = False
        else:
            for host in host_query.json()['data']:
                if host['name'] == hostname:
                    host_registered = True
        message = ('Host registration status for: '+hostname+', OS type: '+os_type+' is: '+str(host_registered))
        LOG.info(message)
        return host_registered
    except Exception as e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong getting host registration status, error: '+str(e))
        return ('Something went wrong getting host registration status, error: '+str(e))

def add_fileset_to_host(hostname=None,fileset_name=None,sla_domain=None,os_type='Linux'):
    '''
    Adds a fileset to a Windows/Linux/Unix host
    '''
    try:
        if not hostname:
            hostname = __grains__['id']
        if not sla_domain:
            LOG.error("No SLA Domain name passed")
            raise ValueError("No SLA Domain name passed")
        if not fileset_name:
            LOG.error("No Fileset Template name passed")
            raise ValueError("No Fileset Template name passed")
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
        if fileset_query.json()['total'] > 0:
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
    except Exception as e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong creating the fileset, error: '+str(e))
        return ('Something went wrong creating the fileset, error: '+str(e))

def check_fileset_configuration(hostname=None,fileset_name=None,sla_domain=None,os_type='Linux'):
    '''
    Checks if a fileset for a Windows/Linux/Unix host exists and is correctly protected
    '''
    try:
        fileset_configured = False
        if not hostname:
            hostname = __grains__['id']
        if not sla_domain:
            LOG.error("No SLA Domain name passed")
            raise ValueError("No SLA Domain name passed")
        if not fileset_name:
            LOG.error("No Fileset Template name passed")
            raise ValueError("No Fileset Template name passed")
        token = _get_token()
        os_type = _normalise_os_type(os_type)
        '''
        Get host ID
        '''
        my_host_id = _get_host_id(hostname,os_type)
        if not my_host_id:
            raise ValueError("No host ID found for "+hostname)
        '''
        Get SLA ID
        '''
        my_sla_id = _get_sla_id(sla_domain)
        if not my_sla_id:
            raise ValueError("No SLA Domain found with name: "+sla_domain)
        '''
        Get fileset template ID
        '''
        my_fst_id = _get_fst_id(fileset_name,os_type)
        if not my_fst_id:
            raise ValueError("No Fileset Template found with name: "+fileset_name)
        '''
        Get fileset ID
        '''
        my_fileset_id = _get_fileset_id(my_host_id,my_fst_id)
        if not my_fileset_id:
            message = 'Fileset does not exist.'
            LOG.info(message)
            return fileset_configured
        '''
        Check fileset SLA
        '''
        my_fileset_sla = _get_fileset_sla(my_fileset_id)
        if not my_fileset_sla:
            raise ValueError("Something went wrong getting the SLA for: "+fileset_name)
        if my_fileset_sla == my_sla_id:
            fileset_configured = True
        return fileset_configured
    except Exception as e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong getting fileset details, error: '+str(e))
        return ('Something went wrong getting fileset details, error: '+str(e))

def get_fileset_list(hostname=None,os_type='Linux'):
    try:
        if not hostname:
            hostname = __grains__['id']
        token = _get_token()
        os_type = _normalise_os_type(os_type)
        '''
        Get host ID
        '''
        my_host_id = _get_host_id(hostname,os_type)
        if not my_host_id:
            raise ValueError("No host ID found for "+hostname)
        '''
        Get fileset list
        '''
        fileset_list = _get_fileset_list(my_host_id)
        return fileset_list
    except Exception as e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong getting fileset list, error: '+str(e))
        return ('Something went wrong getting fileset list, error: '+str(e))


def get_latest_snapshot(hostname=None,object_type='vmware_vm',**kwargs):
    '''
    Returns the latest snapshot date/time for a given object
    '''
    try:
        if not hostname:
            hostname = __grains__['id']
        token = _get_token()
        '''
        Latest snapshot for vmware_vm
        '''
        if object_type == 'vmware_vm':
            vm_id = _get_vmware_vm_id(hostname)
            if not vm_id:
                raise ValueError("No VM found with name "+hostname)
            last_snapshot = _get_latest_snapshot(vm_id)
            return last_snapshot
        '''
        Latest snapshot for fileset
        '''
        if object_type == 'fileset':
            fileset_name = kwargs.get('fileset_name',None)
            os_type = kwargs.get('os_type','Linux')
            os_type = _normalise_os_type(os_type)
            '''
            Get host ID
            '''
            my_host_id = _get_host_id(hostname,os_type)
            if not my_host_id:
                raise ValueError("No host ID found for "+hostname)
            if fileset_name:
                '''
                Get fileset template ID
                '''
                my_fst_id = _get_fst_id(fileset_name,os_type)
                if not my_fst_id:
                    raise ValueError("No Fileset Template found with name: "+fileset_name)
                '''
                Get fileset ID
                '''
                my_fileset_id = _get_fileset_id(my_host_id,my_fst_id)
                if not my_fileset_id:
                    message = 'Fileset does not exist.'
                    LOG.info(message)
                last_snapshot = _get_latest_snapshot(my_fileset_id)
                return last_snapshot
            else:
                '''
                Get fileset list
                '''
                output_list = []
                fileset_list = _get_fileset_list(my_host_id)
                for fileset in fileset_list:
                    this_fileset = fileset
                    this_fileset['last_snapshot'] = _get_latest_snapshot(fileset['id'])
                    output_list.append(this_fileset)
                return output_list
    except Exception as e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong getting latest snapshot, error: '+str(e))
        return ('Something went wrong getting latest snapshot, error: '+str(e))

def snapshotConsistency(hostname=None,mandate="CRASH_CONSISTENT"):
    '''
    Updates the snapshotConsistencyMandate for the given vSphere VM
    '''
    try:
        if not hostname:
            hostname = __grains__['id']
        if not mandate:
            LOG.error("No mandate name passed")
            raise ValueError("No mandate name passed")
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
        '''Compare current Mandate domain to desired one, and update if necessary'''
        if my_vm['snapshotConsistencyMandate'] == mandate:
            LOG.info('Mandate already set to '+mandate)
            return ('Mandate already set to '+mandate)
        else:
            uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm/'+my_vm['id']
            headers = {'Content-Type':'application/json','Accept':'application/json','Authorization':token}
            payload = '{"snapshotConsistencyMandate":"' + mandate + '"}'
            update_mandate = requests.patch(uri, headers=headers, verify=False, data=payload)
            if update_mandate.status_code != 200:
                raise ValueError("Something went wrong setting the Mandate")
            LOG.info('Mandate updated to '+mandate)
            return ('Mandate updated to '+mandate)
    except Exception as e:
        exc_tuple = sys.exc_info()
        LOG.error('Something went wrong setting the Mandate for this VM, error: '+str(e))
        return ('Something went wrong setting the Mandate for this VM, error: '+str(e))

'''
Helper functions
'''
def _get_sla_id(sla_domain=None):
    '''
    Returns the ID of an SLA Domain given the name
    '''
    my_sla = False
    token = _get_token()
    uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/sla_domain?primary_cluster_id=local&name='+sla_domain
    headers = {'Accept':'application/json', 'Authorization':token}
    sla_query = requests.get(uri, headers=headers, verify=False, timeout=15)
    for sla in sla_query.json()['data']:
        if sla['name'] == sla_domain:
            my_sla = sla
    if not my_sla:
        return None
    else:
        return my_sla['id']

def _get_host_id(hostname=None,os_type=None):
    '''
    Returns the ID of a host given the hostname and OS type
    '''
    my_host = False
    token = _get_token()
    uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/host?primary_cluster_id=local&operating_system_type='+os_type+'&name='+hostname
    headers = {'Accept':'application/json', 'Authorization':token}
    host_query = requests.get(uri, headers=headers, verify=False, timeout=15)
    for host in host_query.json()['data']:
        if host['name'] == hostname:
            my_host = host
    if not my_host:
        return None
    else:
        return my_host['id']

def _get_fst_id(fileset_name=None,os_type=None):
    '''
    Returns the ID of a fileset template given the fileset template name and OS type
    '''
    my_fst = False
    token = _get_token()
    uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/fileset_template?primary_cluster_id=local&operating_system_type='+os_type+'&name='+fileset_name
    headers = {'Accept':'application/json', 'Authorization':token}
    fst_query = requests.get(uri, headers=headers, verify=False, timeout=15)
    for fst in fst_query.json()['data']:
        if fst['name'] == fileset_name:
            my_fst = fst
    if not my_fst:
        return None
    else:
        return my_fst['id']

def _get_fileset_list(host_id=None):
    '''
    Returns a tuple of Fileset Name and SLA Domain for all filesets on a given host.
    '''
    fileset_list = []
    token = _get_token()
    uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/fileset?primary_cluster_id=local&is_relic=false&host_id='+host_id
    headers = {'Accept':'application/json', 'Authorization':token}
    fileset_query = requests.get(uri, headers=headers, verify=False, timeout=15)
    for fileset in fileset_query.json()['data']:
        this_fileset = {
            "name":fileset['name'],
            "id":fileset['id'],
            "slaDomainName":fileset['configuredSlaDomainName']
        }
        fileset_list.append(this_fileset)
    return fileset_list

def _get_fileset_id(host_id=None,fst_id=None):
    '''
    Returns the ID of a fileset given the host and fileset template ID
    '''
    fileset_id = False
    token = _get_token()
    uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/fileset?primary_cluster_id=local&is_relic=false&host_id='+host_id+'&template_id='+fst_id
    headers = {'Accept':'application/json', 'Authorization':token}
    fileset_query = requests.get(uri, headers=headers, verify=False, timeout=15)
    if fileset_query.json()['total'] > 0:
        return fileset_query.json()['data'][0]['id']
    else:
        return None

def _get_fileset_sla(fileset_id=None):
    '''
    Returns the ID of a fileset given the host and fileset template ID
    '''
    fileset_sla = False
    token = _get_token()
    uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/fileset/'+fileset_id
    headers = {'Accept':'application/json', 'Authorization':token}
    fileset_query = requests.get(uri, headers=headers, verify=False, timeout=15)
    if fileset_query.json()['configuredSlaDomainId']:
        return fileset_query.json()['configuredSlaDomainId']
    else:
        return None

def _get_vmware_vm_id(vm_name=None):
    '''
    Returns the ID of a VMware VM given the VM name
    '''
    vm_id = False
    token = _get_token()
    headers = {'Accept':'application/json', 'Authorization':token}
    uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm?primary_cluster_id=local&is_relic=false&name='+vm_name
    vm_query = requests.get(uri, headers=headers, verify=False, timeout=15)
    for vm in vm_query.json()['data']:
        if vm['name'] == vm_name:
            vm_id = vm['id']
    return vm_id

def _get_latest_snapshot(object_id):
    '''
    Returns the latest snapshot for a given object
    '''
    object_type = object_id.split(':::')[0]
    token = _get_token()
    headers = {'Accept':'application/json', 'Authorization':token}
    if object_type == 'VirtualMachine': # VMware VM
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/vmware/vm/'+object_id+'/snapshot'
    elif object_type == 'Fileset': # fileset
        uri = 'https://'+__salt__['pillar.get']('rubrik.node','')+'/api/v1/fileset/'+object_id
    else:
        raise ValueError("Unsupported object type: "+object_type)
    snapshot_query = requests.get(uri, headers=headers, verify=False, timeout=15)
    if object_type == 'VirtualMachine': # VMware VM
        if snapshot_query.json()['total'] > 0:
            datestr = snapshot_query.json()['data'][0]['date']
            return str(datetime.datetime.strptime(datestr,'%Y-%m-%dT%H:%M:%S.%fZ'))
        else:
            return None
    elif object_type == 'Fileset': # fileset
        if len(snapshot_query.json()['snapshots']) > 0:
            datestr = snapshot_query.json()['snapshots'][-1]['date']
            return str(datetime.datetime.strptime(datestr,'%Y-%m-%dT%H:%M:%S.%fZ'))
        else:
            return None
    else:
        return None

def _normalise_os_type(os_type):
        if os_type == 'Linux':
            return 'UnixLike'
        elif os_type == 'Windows':
            return 'Windows'
        else:
            return None
