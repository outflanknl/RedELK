#!/usr/bin/python3
#
# Part of RedELK
# Script to check if there are alarms to be sent
#
# Author: Outflank B.V. / Mark Bergman / @xychix
#
import os
from modules.helpers import *
import traceback
import importlib
import datetime

if __name__ == '__main__':
    path = "./modules/"
    module_folders=os.listdir(path)
    print(module_folders)

    mD = {}

    for module in module_folders:
        try:
            m  = importlib.import_module('modules.%s.%s'%(module,'module'))
            if ( hasattr(m,'info') and hasattr(m,'Module') ):
                module_type = m.info.get('type',None)
                print(module_type)
                if module_type == 'redelk_alarm':
                    mD[module] = {}
                    mD[module]['info'] = m.info
                    mD[module]['m'] = m
        except Exception as e:
            print("error in 1: %s" % e)
            stackTrace = traceback.format_exc()
            pass
    print('[i] looping module dict')
    # this means we've loaded the modules and will now loop over those one by one
    for m in mD:
        print('[i] initiating class Module() in %s'%m)
        moduleClass = mD[m]['m'].Module()
        print('[i] Running Run() from the Module class in %s'%m)
        mD[m]['result'] = moduleClass.run()
    #now we can loop over the modules once again and log the lines
    for m in mD:
        r = mD[m]['result']
        for rHit in r['hits']['hits']:
            #loop over alarmed lines
            alarm = {}
            alarm['info'] = mD[m]['info']
            alarm['line'] = rHit
            alarm['@timstamp'] = datetime.datetime.utcnow().isoformat()
            ESindex = "alarms-%s"%datetime.datetime.utcnow().strftime("%Y.%m.%d")
            r = es.index(index=ESindex, ignore=400,  doc_type='_doc', body=alarm)
