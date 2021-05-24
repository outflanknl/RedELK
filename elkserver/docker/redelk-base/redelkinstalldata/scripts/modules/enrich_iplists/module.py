#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
from modules.helpers import get_initial_alarm_result, get_value, raw_search, add_tags_by_query
import traceback
import logging
import datetime

info = {
    'version': 0.1,
    'name': 'Enrich redirtraffic lines with data from IP lists',
    'alarmmsg': '',
    'description': 'This script enriches redirtraffic documents with data from the different IP lists',
    'type': 'redelk_enrich',
    'submodule': 'enrich_iplists'
}


class Module():
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])
        self.now = datetime.datetime.utcnow()

    def run(self):
        ret = get_initial_alarm_result()
        ret['info'] = info

        try:
            self.now = datetime.datetime.utcnow()

            # 1. get all IPs from the different IP lists (except tor)
            ip_lists = self.get_iplists()
            self.logger.info('IP Lists: %s' % ip_lists)

            # 2. Get all entries in redirtraffic that have not the enrich_iplist tag
            redirtraffic = self.get_redirtraffic()

            # 3. loop through each result and find all IPs that matches in redirtraffic
            res = self.update_traffic(ip_lists)

            # 4. Return all hits so they can be tagged
            ret['hits']['hits'] = redirtraffic
            ret['hits']['total'] = res
        except Exception as e:
            stackTrace = traceback.format_exc()
            ret['error'] = stackTrace
            self.logger.exception(e)
            pass
        self.logger.info('finished running module. result: %s hits' % ret['hits']['total'])
        return(ret)

    def get_iplists(self):
        ip_lists = {}
        # Get all IPs except from tor
        q = {'query': {'bool': {'must_not': [{'match': {'iplist.name': 'tor'}}]}}}
        res = raw_search(q, index='redelk-iplist-*')

        if not res:
            return(ip_lists)

        for ipdoc in res['hits']['hits']:
            ip = get_value('_source.iplist.ip', ipdoc)
            iplist_name = get_value('_source.iplist.name', ipdoc)
            # Already one IP found in this list, adding it
            if iplist_name in ip_lists:
                ip_lists[iplist_name].append(ip)
            # First IP for this IP list, creating the array
            else:
                ip_lists[iplist_name] = [ip]

        return(ip_lists)

    def get_redirtraffic(self):
        # Get all redirtraffic before 'now' that were not processed by previous run of the module
        q = {
            'sort': [{'@timestamp': {'order': 'desc'}}],
            'query': {
                'bool': {
                    'filter': [
                        {
                            'range':  {
                                '@timestamp': {
                                    'lte': self.now.isoformat()
                                }
                            }
                        }
                    ],
                    'must_not': [{'match': {'tags': info['submodule']}}]
                }
            }
        }

        res = raw_search(q, index='redirtraffic-*')

        self.logger.debug(res)

        if res is None:
            return([])
        else:
            return(res['hits']['hits'])

    def update_traffic(self, ip_lists):

        updated_count = 0

        # 1. Loop through each IP list
        for iplist_name in ip_lists:
            ip_match = []
            iplist_tag = 'iplist_%s' % iplist_name

            for ip in ip_lists[iplist_name]:
                ip_match.append({'match': {'source.ip': ip}})

            q = {
                'bool': {
                    'must_not': [{'match': {'tags': iplist_tag}}],
                    'should': ip_match,
                    'filter': [
                        {
                            'range':  {
                                '@timestamp': {
                                    'lte': self.now.isoformat()
                                }
                            }
                        }
                    ],
                    'minimum_should_match': 1
                }
            }

            self.logger.debug('Tagging IPs matching IP list %s' % iplist_name)
            # 2. For each IP list, update all documents not tagged already
            res = add_tags_by_query([iplist_tag], q, 'redirtraffic-*')
            updated_count += res['updated']

        return(updated_count)
