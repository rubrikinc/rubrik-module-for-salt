# -*- coding: utf-8 -*-
'''
Module for interacting with Rubrik's API

:maintainer:    Tim Hynes <tim.hynes@rubrik.com>
:depends:       pyRubrik Python module
                requests Python module
'''

import logging
import os
import requests
import salt.utils

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
        log.error "Rubrik node connection issues.  Please check Rubrik node IP address or hostname in the YAML configuration file."

def cluster_info():
    '''
    Return information for the Rubrik cluster
    '''
    try:
        rk = _rubrik_obj()
        return rk.get_public_cluster_info()
    except:
        log.error "Something went wrong getting the cluster information"
