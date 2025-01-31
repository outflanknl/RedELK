#!/usr/bin/python3
"""
Part of RedELK
This script enriches rtops lines with data from initial Sliver implant

Authors:
- Outflank B.V. / Mark Bergman (@xychix)
- Lorenzo Bernardi (@fastlorenzo)
- hypnoticpattern
"""

import logging
import traceback

from modules.helpers import es, get_initial_alarm_result, get_query, get_value

info = {
    'version': 0.1,
    'name': 'Enrich Sliver implant data',
    'alarmmsg': '',
    'description': 'This script enriches rtops lines with data from initial Sliver session',
    'type': 'redelk_enrich',
    'submodule': 'enrich_sliver'
}


class Module():
    """ enrich sliver module """
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])

    def run(self):
        """ run the enrich module """
        ret = get_initial_alarm_result()
        ret['info'] = info
        hits = self.enrich_sliver_data()
        ret['hits']['hits'] = hits
        ret['hits']['total'] = len(hits)
        self.logger.info('finished running module. result: %s hits', ret['hits']['total'])
        return ret

    def enrich_sliver_data(self):
        """ Get all lines in rtops that have not been enriched yet (for Sliver) """
        es_query = f'implant.id:* AND c2.program: sliver AND NOT c2.log.type:implant_newsession AND NOT tags:{info["submodule"]}'
        not_enriched_results = get_query(es_query, size=10000, index='rtops-*')

        # Created a dict grouped by implant ID
        implant_ids = {}
        for not_enriched in not_enriched_results:
            implant_id = get_value('_source.implant.id', not_enriched)
            if implant_id in implant_ids:
                implant_ids[implant_id].append(not_enriched)
            else:
                implant_ids[implant_id] = [not_enriched]

        hits = []
        # For each implant ID, get the initial session line
        for implant_id, implant_val in implant_ids.items():
            initial_sliver_session_doc = self.get_initial_sliver_session_doc(implant_id)

            # If not initial session line found, skip the session ID
            if not initial_sliver_session_doc:
                continue

            for doc in implant_val:
                # Fields to copy: host.*, implant.*, process.*, user.*
                res = self.copy_data_fields(initial_sliver_session_doc, doc, ['host', 'implant', 'user', 'process'])
                if res:
                    hits.append(res)

        return hits

    def get_initial_sliver_session_doc(self, implant_id):
        """ Get the initial implant document from Sliver or return False if none found """
        query = f'implant.id:{implant_id} AND c2.program: sliver AND c2.log.type:implant_newsession'
        initial_sliversession_doc = get_query(query, size=1, index='rtops-*')
        initial_sliversession_doc = initial_sliversession_doc[0] if len(initial_sliversession_doc) > 0 else False
        self.logger.debug('Initial sliver session line [%s]: %s', implant_id, initial_sliversession_doc)
        return initial_sliversession_doc

    def copy_data_fields(self, src, dst, fields):
        """ Copy all data of [fields] from src to dst document and save it to ES """
        for field in fields:
            if field in dst['_source']:
                self.logger.info('Field [%s] already exists in destination document, it will be overwritten', field)            
            dst['_source'][field] = src['_source'][field]

        try:
            es.update(index=dst['_index'], id=dst['_id'], body={'doc': dst['_source']})
            return dst
        # pylint: disable=broad-except
        except Exception as error:
            # stackTrace = traceback.format_exc()
            self.logger.error('Error enriching sliver session document %s: %s', dst['_id'], traceback)
            self.logger.exception(error)
            return False