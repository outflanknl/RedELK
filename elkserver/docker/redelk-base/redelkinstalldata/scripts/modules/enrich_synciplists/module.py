#!/usr/bin/python3
#
# Part of RedELK
#
# Authors:
# - Outflank B.V. / Mark Bergman (@xychix)
# - Lorenzo Bernardi (@fastlorenzo)
#
from modules.helpers import get_initial_alarm_result, get_query, get_value, es
import traceback
import logging
import re
import datetime
import os.path

IP_RE = '^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))(\s?#\s?(.*))?$'
IP_CIDR_RE = '^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([1-2][0-9]|3[0-2]|[0-9])))(\s?#\s?(.*))?$'

info = {
    'version': 0.1,
    'name': 'Enrich sync iplist',
    'alarmmsg': '',
    'description': 'Syncs iplists data between ES and legacy config files',
    'type': 'redelk_enrich',
    'submodule': 'enrich_synciplists'
}


class Module():
    def __init__(self):
        self.logger = logging.getLogger(info['submodule'])
        self.iplists = ['customer', 'redteam', 'unknown', 'blueteam']

    def run(self):
        ret = get_initial_alarm_result()
        ret['info'] = info
        try:
            hits = []
            for iplist in self.iplists:
                self.sync_iplist(iplist)
            ret['hits']['hits'] = hits
            ret['hits']['total'] = len(hits)
        except Exception as e:
            stackTrace = traceback.format_exc()
            ret['error'] = stackTrace
            self.logger.exception(e)
            pass
        self.logger.info('finished running module. result: %s hits' % ret['hits']['total'])
        return(ret)

    def sync_iplist(self, iplist='redteam'):
        # Get data from config file iplist
        cfg_iplist = []
        fname = '/etc/redelk/iplist_%s.conf' % iplist

        # Check first if the local config file exists; if not, skip the sync
        if not os.path.isfile(fname):
            self.logger.warning('File %s doesn\'t exist, skipping IP list sync for this one.' % fname)
            return

        with open(fname, 'r') as f:
            content = f.readlines()

        for line in content:
            m = re.match(IP_CIDR_RE, line)
            if m:
                cfg_iplist.append((m.group(1), m.group(len(m.groups()))))
            else:
                m = re.match(IP_RE, line)
                if m:
                    cfg_iplist.append(('%s/32' % m.group(1), m.group(len(m.groups()))))

        # Get data from ES iplist
        query = 'iplist.name:%s' % iplist
        es_iplist_docs = get_query(query, size=10000, index='redelk-*')

        # Check if config IP is in ES and source = config_file
        es_iplist = []
        for doc in es_iplist_docs:
            ip = get_value('_source.iplist.ip', doc)
            if ip:
                es_iplist.append((ip, doc))

        for ipc, comment in cfg_iplist:
            found = [item for item in es_iplist if ipc in item]
            if not found:
                self.logger.debug('IP not found in ES: %s' % ipc)
                # if not, add it
                self.add_es_ip(ipc, iplist, comment)

        toadd = []
        for ipe, doc in es_iplist:
            # Check if ES IP is in config file
            found = [item for item in cfg_iplist if ipe in item]
            if not found:
                # if not, check if source = config_file
                if get_value('_source.iplist.source', doc) == 'config_file':
                    # if yes, remove IP from ES
                    self.remove_es_ip(doc, iplist)
                else:
                    # if not, add it
                    comment = get_value('_source.iplist.comment', doc)
                    if comment:
                        ipa = '%s # From ES -- %s' % (ipe, comment)
                    else:
                        ipa = '%s # From ES' % ipe
                    toadd.append(ipa)

        self.add_cfg_ips(toadd, iplist)

        return(toadd)

    # Add IPs to cfg file
    def add_cfg_ips(self, toadd, iplist):
        try:
            fname = '/etc/redelk/iplist_%s.conf' % iplist
            with open(fname, 'a') as f:
                for ipl in toadd:
                    f.write('%s\n' % ipl)
        except Exception as e:
            self.logger.error('Failed to update %s: %s' % (fname, e))
            self.logger.exception(e)
            raise

    def add_es_ip(self, ip, iplist, comment=None):
        try:
            ts = datetime.datetime.utcnow().isoformat()
            doc = {
                "@timestamp": ts,
                "iplist": {
                    "name": iplist,
                    "source": "config_file",
                    "ip": ip
                }
            }

            if comment:
                doc['iplist']['comment'] = comment

            index = 'redelk-iplist-%s' % iplist
            es.index(index=index, body=doc)

        except Exception as e:
            self.logger.error('Failed to add IP %s in %s: %s' % (ip, iplist, e))
            self.logger.exception(e)
            raise

    def remove_es_ip(self, doc, iplist):
        try:
            index = 'redelk-iplist-%s' % iplist
            es.delete(index=index, id=doc['_id'])

        except Exception as e:
            self.logger.error('Failed to delete doc %s from %s: %s' % (doc['_id'], iplist, e))
            self.logger.exception(e)
            raise
