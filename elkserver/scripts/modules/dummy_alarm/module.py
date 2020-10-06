#!/usr/bin/python3
#
# Part of RedELK
#
# Author: Lorenzo Bernardi / @fastlorenzo
#
from modules.helpers import *
import traceback

info = {
    'version': 0.1,
    'name': 'dummy_alarm module',
    'description': 'This alarm always triggers. Only use for testing purposes',
    'type': 'redelk_alarm',
    'submodule': 'dummy_alarm'
}


class Module():
    def __init__(self):
        #print("class init")
        pass

    def run(self):
        ret = {}
        alarmLines = []

        ret['info'] = info
        ret['hits'] = {}
        ret['hits']['hits'] = []
        ret['hits']['total'] = 1
        ret['results'] = {
            'test': {
                'key': 'val'
            }
        }
        print("[a] finished running module %s . result: %s hits"%(ret['info']['name'],ret['hits']['hits']))
        #print(ret)
        return(ret)
