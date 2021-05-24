#!/usr/bin/python3
"""
Part of RedELK

Script to check if there are alarms to be sent

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
"""

import copy
import importlib
import logging
import os

from config import alarms, LOGLEVEL, notifications
from modules.helpers import (add_alarm_data, group_hits, module_did_run, set_tags,
                             module_should_run)

MODULES_PATH = './modules/'

def load_modules():
    """ Attempt to load the different modules in their respective dictionaries, and return them """
    alarm_dict = {}  # aD alarm Dict
    connector_dict = {}  # cD connector Dict
    enrich_dict = {}  # eD enrich Dict
    module_folders = os.listdir(MODULES_PATH)

    for module in module_folders:
        # only take folders and not '__pycache__'
        if os.path.isdir(os.path.join(MODULES_PATH, module)) and module != '__pycache__':
            try:
                module = importlib.import_module(
                    'modules.%s.%s' % (module, 'module'))
                if (hasattr(module, 'info') and hasattr(module, 'Module')):
                    module_type = module.info.get('type', None)
                    if module_type == 'redelk_alarm':
                        alarm_dict[module] = {}
                        alarm_dict[module]['info'] = module.info
                        alarm_dict[module]['m'] = module
                        alarm_dict[module]['status'] = 'pending'
                    elif module_type == 'redelk_connector':
                        connector_dict[module] = {}
                        connector_dict[module]['info'] = module.info
                        connector_dict[module]['m'] = module
                        connector_dict[module]['status'] = 'pending'
                    elif module_type == 'redelk_enrich':
                        enrich_dict[module] = {}
                        enrich_dict[module]['info'] = module.info
                        enrich_dict[module]['m'] = module
                        enrich_dict[module]['status'] = 'pending'
            # pylint: disable=broad-except
            except Exception as error:
                logger.error('Error in module %s: %s', module, error)
                logger.exception(error)
    return(alarm_dict, connector_dict, enrich_dict)

def run_enrichments(enrich_dict):
    """ Run the different enrichment scripts that are enabled """
    logger.info('Running enrichment modules')
    # First loop through the enrichment modules
    for enrich_module in enrich_dict:
        if module_should_run(enrich_module, 'redelk_enrich'):
            try:
                logger.debug('[e] initiating class Module() in %s', enrich_module)
                module_class = enrich_dict[enrich_module]['m'].Module()
                logger.debug('[e] Running Run() from the Module class in %s', enrich_module)
                enrich_dict[enrich_module]['result'] = copy.deepcopy(module_class.run())

                # Now loop through the hits and tag them
                for hit in enrich_dict[enrich_module]['result']['hits']['hits']:
                    set_tags(enrich_dict[enrich_module]['info']['submodule'], [hit])

                hits = len(enrich_dict[enrich_module]['result']['hits']['hits'])
                module_did_run(enrich_module, 'enrich', 'success', 'Enriched %s documents' % hits, hits)
                enrich_dict[enrich_module]['status'] = 'success'
            # pylint: disable=broad-except
            except Exception as err:
                msg = 'Error running enrichment %s: %s' % (enrich_module, err)
                logger.error(msg)
                logger.exception(err)
                module_did_run(enrich_module, 'enrich', 'error', msg)
                enrich_dict[enrich_module]['status'] = 'error'
    return enrich_dict

def run_alarms(alarm_dict):
    """ Run the different alarm scripts that are enabled and return the results """
    logger.info('Running alarm modules')
    # this means we've loaded the modules and will now loop over those one by one
    for alarm_module in alarm_dict:
        if module_should_run(alarm_module, 'redelk_alarm'):
            try:
                logger.debug('[a] initiating class Module() in %s', alarm_module)
                module_class = alarm_dict[alarm_module]['m'].Module()
                logger.debug('[a] Running Run() from the Module class in %s', alarm_module)
                alarm_dict[alarm_module]['result'] = copy.deepcopy(module_class.run())
                hits = len(alarm_dict[alarm_module]['result']['hits']['hits'])
                module_did_run(alarm_module, 'alarm', 'success', 'Found %s documents to alarm' % hits, hits)
                alarm_dict[alarm_module]['status'] = 'success'
            # pylint: disable=broad-except
            except Exception as error:
                msg = 'Error running alarm %s: %s' % (alarm_module, error)
                logger.error(msg)
                logger.exception(error)
                module_did_run(alarm_module, 'alarm', 'error', msg)
                alarm_dict[alarm_module]['status'] = 'error'
    return alarm_dict

def process_alarms(connector_dict, alarm_dict):
    """ Process the alarm results and send notifications via connector modules """
    logger.info('Processing alarms')
    # now we can loop over the modules once again and log the lines
    for alarm in alarm_dict:
        if alarm in alarms and alarms[alarm]['enabled']:

            # If the alarm did fail to run, skip processing the notification and tagging as we are not sure of the results
            if alarm_dict[alarm]['status'] != 'success':
                logger.warning('Alarm %s did not run (correctly), skipping processing', alarm)
                continue

            logger.debug('Alarm %s enabled, processing hits', alarm)
            result = alarm_dict[alarm]['result']
            alarm_name = alarm_dict[alarm]['info']['submodule']
            # logger.debug('Alarm results: %s' % aD[a]['result'])
            for result_hits in result['hits']['hits']:
                # First check if there is a mutation data to add
                logger.debug(result_hits)
                if result_hits['_id'] in result['mutations']:
                    mutations = result['mutations'][result_hits['_id']]
                else:
                    mutations = {}
                # And now, let's add mutations data to the doc and update back the hits
                result_hits = add_alarm_data(result_hits, mutations, alarm_name)

            # Let's tag the docs with the alarm name
            set_tags(alarm_name, result['hits']['hits'])
            logger.debug('calling settags %s (%d hits)', alarm_name, result['hits']['total'])

            # Needed as groupHits will change r['hits']['hits'] and different alarms might do different grouping
            result = copy.deepcopy(alarm_dict[alarm]['result'])
            if result['hits']['total'] > 0:
                # Group the hits before sending it to the alarm, based on the 'groubpby' array returned by the alarm
                group_by = list(result['groupby'])
                result['hits']['hits'] = group_hits(result['hits']['hits'], group_by)

                for connector in connector_dict:
                    # connector will process ['hits']['hits'] which contains a list of 'jsons' looking like an ES line
                    # connector will report the fields in ['hits']['fields'] for each of the lines in the list
                    if connector in notifications and notifications[connector]['enabled']:
                        connector_mod = connector_dict[connector]['m'].Module()
                        logger.info('connector %s enabled, sending alarm (%d hits)', connector, result['hits']['total'])
                        connector_mod.send_alarm(result)


# Main entry point of the file
if __name__ == '__main__':
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(name)s - %(filename)s - %(funcName)s -- %(message)s', level=LOGLEVEL)
    logger = logging.getLogger('alarm')

    # 1. Load all modules
    (aD, cD, eD) = load_modules()

    # 2. Run enrichment modules
    eD = run_enrichments(eD)

    # 3. Run alarm modules
    aD = run_alarms(aD)

    # 4. Process the alarms generated by alarm modules
    process_alarms(cD, aD)
