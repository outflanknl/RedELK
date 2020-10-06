#!/usr/bin/python3
#
# Part of RedELK
# Script to check if there are alarms to be sent
#
# Author: Outflank B.V. / Mark Bergman / @xychix
# Contributor: Lorenzo Bernardi / @fastlorenzo
#
import os
from modules.helpers import *
import traceback
import importlib
import datetime

if __name__ == '__main__':
    path = './modules/'
    module_folders = os.listdir(path)
    print(module_folders)

    connectors_path = './modules/'
    connectors_folders = os.listdir(connectors_path)

    aD = {} #aD alarm Dict
    cD = {} #cD connector Dict

    for module in module_folders:
        # only take folders and not '__pycache__'
        if os.path.isdir(os.path.join(path, module)) and module != '__pycache__':
            try:
                m = importlib.import_module(
                    'modules.%s.%s' % (module, 'module'))
                if (hasattr(m, 'info') and hasattr(m, 'Module')):
                    module_type = m.info.get('type', None)
                    print(module_type)
                    if module_type == 'redelk_alarm':
                        aD[module] = {}
                        aD[module]['info'] = m.info
                        aD[module]['m'] = m
                    elif module_type == 'redelk_connector':
                        cD[module] = {}
                        cD[module]['info'] = m.info
                        cD[module]['m'] = m
            except Exception as e:
                print('[e] error in module %s: %s' % (module, e))
                stackTrace = traceback.format_exc()
                pass

    print('[i] looping module dict')
    # this means we've loaded the modules and will now loop over those one by one
    for a in aD:
        print('[a] initiating class Module() in %s' % a)
        moduleClass = aD[a]['m'].Module()
        print('[a] Running Run() from the Module class in %s' % a)
        aD[a]['result'] = moduleClass.run()

    # now we can loop over the modules once again and log the lines
    for a in aD:
        r = aD[a]['result']
        for rHit in r['hits']['hits']:
            # loop over alarmed lines
            alarm = {}
            alarm['info'] = aD[a]['info']
            alarm['line'] = rHit
            alarm['@timstamp'] = datetime.datetime.utcnow().isoformat()
            ESindex = 'alarms-%s' % datetime.datetime.utcnow().strftime('%Y.%m.%d')
            ri = es.index(index=ESindex, ignore=400,
                         doc_type='_doc', body=alarm)
        for c in cD:
            connector = cD[c]['m'].Module()
            #print(pprint(r))
            if r['hits']['total'] > 0:
                connector.send_alarm(r)
            pass
