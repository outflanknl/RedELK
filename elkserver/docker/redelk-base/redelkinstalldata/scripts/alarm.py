#!/usr/bin/python3
#
# Part of RedELK
# Script to check if there are alarms to be sent
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
import os
import traceback
import importlib
import datetime
import logging
import copy

from modules.helpers import *
from config import alarms, notifications
import config as localconfig
import itertools

if localconfig.DEBUG:
    LOG_LEVEL = logging.DEBUG
else:
    LOG_LEVEL = logging.INFO

if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(name)s - %(filename)s - %(funcName)s -- %(message)s', level=LOG_LEVEL)
    logger = logging.getLogger('alarm')
    path = './modules/'
    module_folders = os.listdir(path)
    logger.debug(module_folders)

    connectors_path = './modules/'
    connectors_folders = os.listdir(connectors_path)

    aD = {}  # aD alarm Dict
    cD = {}  # cD connector Dict

    for module in module_folders:
        # only take folders and not '__pycache__'
        if os.path.isdir(os.path.join(path, module)) and module != '__pycache__':
            try:
                m = importlib.import_module(
                    'modules.%s.%s' % (module, 'module'))
                if (hasattr(m, 'info') and hasattr(m, 'Module')):
                    module_type = m.info.get('type', None)
                    if module_type == 'redelk_alarm':
                        aD[module] = {}
                        aD[module]['info'] = m.info
                        aD[module]['m'] = m
                    elif module_type == 'redelk_connector':
                        cD[module] = {}
                        cD[module]['info'] = m.info
                        cD[module]['m'] = m
            except Exception as e:
                logger.error('Error in module %s: %s' % (module, e))
                logger.exception(e)
                pass

    logger.info('Looping module dict')
    # this means we've loaded the modules and will now loop over those one by one
    for a in aD:
        logger.debug(alarms)
        if a in alarms and alarms[a]['enabled'] == True:
            try:
                logger.info('[a] initiating class Module() in %s' % a)
                moduleClass = aD[a]['m'].Module()
                logger.info('[a] Running Run() from the Module class in %s' % a)
                aD[a]['result'] = copy.deepcopy(moduleClass.run())
            except Exception as e:
                logger.error('Error running alarm %s: %s' % (a, e))
                logger.exception(e)

    # now we can loop over the modules once again and log the lines
    for a in aD:
        if a in alarms and alarms[a]['enabled']:
            logger.debug('Alarm %s enabled, processing hits' % a)
            r = aD[a]['result']
            alarm_name = aD[a]['info']['submodule']
            #logger.debug('Alarm results: %s' % aD[a]['result'])
            for rHit in r['hits']['hits']:
                # First check if there is a mutation data to add
                if rHit['_id'] in r['mutations']:
                    m = r['mutations'][rHit['_id']]
                else:
                    m = {}
                # And now, let's add mutations data to the doc and update back the hits
                rHit = addAlarmData(rHit, m, alarm_name)
            # Let's tag the doc with the alarm name
            setTags(alarm_name, r['hits']['hits'])
            logger.info('calling settags %s  (%d hits)' % (alarm_name, r['hits']['total']))
            # Needed as groupHits will change r['hits']['hits'] and different alarms might do different grouping
            r = copy.deepcopy(aD[a]['result'])
            for c in cD:
                # connector will process ['hits']['hits'] which contains a list of 'jsons' looking like an ES line
                # connector will report the fields in ['hits']['fields'] for each of the lines in the list
                if c in notifications and notifications[c]['enabled']:
                    connector = cD[c]['m'].Module()
                    if r['hits']['total'] > 0:
                        logger.info('connector %s enabled, sending alarm (%d hits)' % (c, r['hits']['total']))
                        # Group the hits before sending it to the alarm, based on the 'groubpby' array returned by the alarm
                        gb = list(r['groupby'])
                        r['hits']['hits'] = groupHits(r['hits']['hits'], gb)
                        connector.send_alarm(r)
