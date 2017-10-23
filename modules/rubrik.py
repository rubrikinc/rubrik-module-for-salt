# -*- coding: utf-8 -*-
'''
Module for interacting with Rubrik's API

:depends:   -   pyRubrik Python module
                requests Python module
'''

import logging, os

try:
    import pyRubrik as RubrikClient
    HAS_DEPS = True
except ImportError:
    HAS_DEPS = False

def _rubrik_obj():
    '''
    Return a new Rubrik object given API credentials provided via pillar
    '''
    return RubrikClient.create(__salt__['pillar.get']('rubrik:node',''), __salt__['pillar.get']('rubrik:username',''), __salt__['pillar.get']('rubrik:password',''))

def 