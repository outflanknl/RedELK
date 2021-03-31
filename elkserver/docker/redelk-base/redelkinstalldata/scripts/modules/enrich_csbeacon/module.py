#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
from modules.helpers import getQuery, getValue, get_initial_alarm_result, es
import traceback
import logging

info = {
    'version': 0.1,
    'name': 'Enrich Cobalt Strike beacon data',
    'alarmmsg': '',
    'description': 'This script enriches rtops lines with data from initial Cobalt Strike beacon',
    'type': 'redelk_enrich',
    'submodule': 'enrich_csbeacon'
}


class Module():
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])

    def run(self):
        ret = get_initial_alarm_result()
        ret['info'] = info
        try:
            hits = self.enrich_beacon_data()
            ret['hits']['hits'] = hits
            ret['hits']['total'] = len(hits)
        except Exception as e:
            stackTrace = traceback.format_exc()
            ret['error'] = stackTrace
            self.logger.exception(e)
            pass
        self.logger.info('finished running module. result: %s hits' % ret['hits']['total'])
        return(ret)

    def enrich_beacon_data(self):
        # Get all lines in rtops that have not been enriched yet (for CS)
        query = 'implant.id:* AND c2.program: cobaltstrike AND NOT c2.log.type:implant_newimplant AND NOT tags:%s' % info['submodule']
        notEnriched = getQuery(query, size=10000, index='rtops-*')

        # Created a dict grouped by implant ID
        implantIds = {}
        for ne in notEnriched:
            implantId = getValue('_source.implant.id', ne)
            if implantId in implantIds:
                implantIds[implantId].append(ne)
            else:
                implantIds[implantId] = [ne]

        hits = []
        # For each implant ID, get the initial beacon line
        for iID in implantIds:
            initialBeaconDoc = self.get_initial_beacon_doc(iID)

            # If not initial beacon line found, skip the beacon ID
            if not initialBeaconDoc:
                continue

            for doc in implantIds[iID]:
                # Fields to copy: host.*, implant.*, process.*, user.*
                res = self.copy_data_fields(initialBeaconDoc, doc, ['host', 'implant', 'user', 'process'])
                if res:
                    hits.append(res)

        return(hits)

    # Get the initial beacon document from cobaltstrike or return False if none found
    def get_initial_beacon_doc(self, implantId):
        query = 'implant.id:%s AND c2.program: cobaltstrike AND c2.log.type:implant_newimplant' % implantId
        initialBeaconDoc = getQuery(query, size=1, index="rtops-*")
        initialBeaconDoc = initialBeaconDoc[0] if len(initialBeaconDoc) > 0 else False
        self.logger.debug('Initial beacon line [%s]: %s' % (implantId, initialBeaconDoc))
        return(initialBeaconDoc)

    # Copy all data of [fields] from src to dst document and save it to ES
    def copy_data_fields(self, src, dst, fields):
        for f in fields:
            if f in dst['_source']:
                self.logger.info('Field [%s] already exists in destination document, it will be overwritten' % f)
            dst['_source'][f] = src['_source'][f]

        try:
            es.update(index=dst['_index'], id=dst['_id'], body={'doc': dst['_source']})
            return(dst)
        except Exception as e:
            # stackTrace = traceback.format_exc()
            self.logger.error('Error enriching beacon document %s: %s' % (dst['_id'], traceback))
            self.logger.exception(e)
            return(False)
