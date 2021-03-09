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
import importlib
import logging
import copy

from modules.helpers import shouldModuleRun, setTags, moduleDidRun, addAlarmData, groupHits
from config import alarms, notifications, enrich, LOGLEVEL
import config as conf

if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(name)s - %(filename)s - %(funcName)s -- %(message)s', level=LOGLEVEL)
    logger = logging.getLogger('alarm')
    path = './modules/'
    module_folders = os.listdir(path)
    logger.debug(module_folders)

    connectors_path = './modules/'
    connectors_folders = os.listdir(connectors_path)

    aD = {}  # aD alarm Dict
    cD = {}  # cD connector Dict
    eD = {}  # eD enrich Dict

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
                        aD[module]['status'] = 'pending'
                    elif module_type == 'redelk_connector':
                        cD[module] = {}
                        cD[module]['info'] = m.info
                        cD[module]['m'] = m
                        cD[module]['status'] = 'pending'
                    elif module_type == 'redelk_enrich':
                        eD[module] = {}
                        eD[module]['info'] = m.info
                        eD[module]['m'] = m
                        eD[module]['status'] = 'pending'
            except Exception as e:
                logger.error('Error in module %s: %s' % (module, e))
                logger.exception(e)
                pass

    # First loop through the enrichment modules
    for e in eD:
        if shouldModuleRun(e, 'redelk_enrich'):
            try:
                logger.info('[e] initiating class Module() in %s' % e)
                moduleClass = eD[e]['m'].Module()
                logger.info('[e] Running Run() from the Module class in %s' % e)
                eD[e]['result'] = copy.deepcopy(moduleClass.run())

                # Now loop through the hits and tag them
                for rHit in eD[e]['result']['hits']['hits']:
                    setTags(eD[e]['info']['submodule'], [rHit])

                hits = len(eD[e]['result']['hits']['hits'])
                moduleDidRun(e, 'enrich', 'success', 'Enriched %s documents' % hits)
                eD[e]['status'] = 'success'
            except Exception as err:
                msg = 'Error running enrichment %s: %s' % (e, err)
                logger.error(msg)
                logger.exception(err)
                moduleDidRun(e, 'enrich', 'error', msg)
                eD[e]['status'] = 'error'

    logger.info('Looping module dict')
    # this means we've loaded the modules and will now loop over those one by one
    for a in aD:
        if shouldModuleRun(a, 'redelk_alarm'):
            try:
                logger.info('[a] initiating class Module() in %s' % a)
                moduleClass = aD[a]['m'].Module()
                logger.info('[a] Running Run() from the Module class in %s' % a)
                aD[a]['result'] = copy.deepcopy(moduleClass.run())
                hits = len(aD[a]['result']['hits']['hits'])
                moduleDidRun(a, 'alarm', 'success', 'Found %s documents to alarm' % hits)
                aD[a]['status'] = 'success'
            except Exception as e:
                msg = 'Error running alarm %s: %s' % (a, e)
                logger.error(msg)
                logger.exception(e)
                moduleDidRun(a, 'alarm', 'error', msg)
                aD[a]['status'] = 'error'

    # now we can loop over the modules once again and log the lines
    for a in aD:
        if a in alarms and alarms[a]['enabled']:

            # If the alarm did fail to run, skip processing the notification and tagging as we are not sure of the results
            if aD[a]['status'] != 'success':
                logger.info('Alarm %s did not run (correctly), skipping processing' % a)
                continue

            logger.debug('Alarm %s enabled, processing hits' % a)
            r = aD[a]['result']
            # logger.debug('Alarm results: %s' % aD[a]['result'])
            for rHit in r['hits']['hits']:
                alarm_name = aD[a]['info']['submodule']
                # Let's tag the doc with the alarm name
                setTags(alarm_name, [rHit])
                # First check if there is a mutation data to add
                if rHit['_id'] in r['mutations']:
                    m = r['mutations'][rHit['_id']]
                else:
                    m = {}
                # And now, let's add mutations data to the doc and update back the hits
                rHit = addAlarmData(rHit, m, alarm_name)
            # Needed as groupHits will change r['hits']['hits'] and different alarms might do different grouping
            r = copy.deepcopy(aD[a]['result'])
            for c in cD:
                # connector will process ['hits']['hits'] which contains a list of 'jsons' looking like an ES line
                # connector will report the fields in ['hits']['fields'] for each of the lines in the list
                if c in notifications and notifications[c]['enabled']:
                    logger.info('connector %s enabled, sending alarm (%d hits)' % (c, r['hits']['total']))
                    connector = cD[c]['m'].Module()
                    if r['hits']['total'] > 0:
                        # Group the hits before sending it to the alarm, based on the 'groubpby' array returned by the alarm
                        gb = list(r['groupby'])
                        r['hits']['hits'] = groupHits(r['hits']['hits'], gb)
                        connector.send_alarm(r)
