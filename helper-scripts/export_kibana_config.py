#!/usr/bin/python3
import ndjson
import json
import requests
import re
import argparse
import sys
import os
from pprint import pprint

# Quick hack to disable invalid cert warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCHEME = 'https'
KIBANA_URL = SCHEME + '://localhost:5601'
KIBANA_OBJECTS_EXPORT_URL = KIBANA_URL + '/api/saved_objects/_export'
REDELK_OBJ_FILTER = 'RedELK'
INDEX_PATTERNS_FILTER = 'rtops|redirtraffic|implantsdb|bluecheck|credentials|email|redelk|.siem-signals'
EXPORT_FILES_PREFIX_KIBANA = 'redelk_kibana_'
ES_URL = SCHEME + '://localhost:9200'
ES_TEMPLATES_LIST = ['rtops', 'redirtraffic', 'implantsdb', 'bluecheck', 'credentials', 'email', 'redelk']
EXPORT_FILES_PREFIX_ES = 'redelk_elasticsearch_'
DIFF_PATH = 'diff/'  # path is relative to exportpath
PASSW_FILE = '../elkserver/.env'


def fetch_kibana_object(obj_type, exportpath):
    try:
        print('# Fetching kibana objects: %s' % obj_type)
        response = requests.post(KIBANA_OBJECTS_EXPORT_URL, json={'type': obj_type}, verify=False, auth=(KIBANA_USER, KIBANA_PASS), headers={'kbn-xsrf': 'true'})
        if response.status_code != 200:
            print('!!! Error fetching kibana object %s: HTTP status code %s' % (obj_type, response.status_code))
        else:
            rawData = response.text.encode('utf-8')
            items = ndjson.loads(rawData)
            if obj_type != 'index-pattern':
                toExport = []
                for ip in items:
                    if 'attributes' in ip.keys() and 'title' in ip['attributes']:
                        if re.match(REDELK_OBJ_FILTER, ip['attributes']['title'], re.IGNORECASE):
                            ip.pop('updated_at', None)
                            ip['version'] = '1'
                            toExport.append(ip)
                export_file = os.path.join(exportpath, '%s%s.ndjson' % (EXPORT_FILES_PREFIX_KIBANA, obj_type))
                print('\tExporting %s: %s' % (obj_type, export_file))
                with open(export_file, 'w') as f:
                    ndjson.dump(toExport, f)
            else:
                for ip in items:
                    if 'attributes' in ip.keys() and 'title' in ip['attributes']:
                        if re.match(INDEX_PATTERNS_FILTER, ip['attributes']['title'], re.IGNORECASE):
                            # print('%s: %s' % (obj_type,ip['attributes']['title']))
                            pn = ip['attributes']['title'][:-2] if ip['attributes']['title'].endswith('-*') else ip['attributes']['title']
                            ip.pop('updated_at', None)
                            ip['version'] = '1'
                            export_file = os.path.join(exportpath, '%s%s_%s.ndjson' % (EXPORT_FILES_PREFIX_KIBANA, obj_type, pn))
                            print('\tExporting %s: %s' % (obj_type, export_file))
                            with open(export_file, 'w') as f:
                                ndjson.dump([ip], f)
    except Exception as e:
        print('!!! Error fetching kibana object %s: %s' % (obj_type, e))


def fetch_es_templates(exportpath):
    for i in ES_TEMPLATES_LIST:
        try:
            print('# Fetching ES template: %s' % i)
            response = requests.get('%s/_template/%s' % (ES_URL, i), verify=False, auth=(KIBANA_USER,KIBANA_PASS))
            rawData = response.text.encode('utf-8')
            tmpl = json.loads(rawData)
            export_file = os.path.join(exportpath, '%stemplate_%s.json' % (EXPORT_FILES_PREFIX_ES, i))
            print('\tExporting index template %s: %s' % (i, export_file))
            with open(export_file, 'w') as f:
                json.dump(tmpl[i], f, indent=4, sort_keys=True)
        except Exception as e:
            print('!!! Error fetching ES template %s: %s' % (i, e))

def process_kibana_object(obj_type, exportpath, indexpattern=None):
    print('# Processing kibana object: %s' % obj_type)

    if obj_type != 'index-pattern':
        src_file_name = '%s%s' % (EXPORT_FILES_PREFIX_KIBANA, obj_type)
    else:
        if indexpattern is None:
            for i in INDEX_PATTERNS_FILTER.split('|'):
                process_kibana_object(obj_type, exportpath, indexpattern=i)
            return
        else:
            src_file_name = '%s%s_%s' % (EXPORT_FILES_PREFIX_KIBANA, obj_type, indexpattern)

    src_file = os.path.join(exportpath, '%s.ndjson' % src_file_name)
    diff_file = os.path.join(exportpath, DIFF_PATH, '%s.json' % src_file_name)
    print('\tOpening %s: %s' % (obj_type, src_file))
    with open(src_file, 'r') as f:
        src_ndjson = ndjson.load(f)

    for s in src_ndjson:
        if obj_type == 'index-pattern':
            s['attributes']['fields'] = sorted(json.loads(s['attributes']['fields']), key=lambda x : x['name'])
        elif obj_type == 'search':
            s['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'] = json.loads(s['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])
        elif obj_type == 'visualization':
            s['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'] = json.loads(s['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])
            s['attributes']['visState'] = json.loads(s['attributes']['visState'])
        elif obj_type == 'dashboard':
            s['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'] = json.loads(s['attributes']['kibanaSavedObjectMeta']['searchSourceJSON'])
            s['attributes']['optionsJSON'] = json.loads(s['attributes']['optionsJSON'])
            s['attributes']['panelsJSON'] = json.loads(s['attributes']['panelsJSON'])

    print('\tWriting output to: %s' % diff_file)
    with open(diff_file, 'w') as f:
        json.dump(src_ndjson, f, indent=4, sort_keys=True)

def check_args():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--exportpath", metavar="<exportpath>", dest="exportpath", help="Path to export the objects")
    parser.add_argument("--indexpattern", action='store_true', help="Export Kibana index patterns")
    parser.add_argument("--search", action='store_true', help="Export Kibana searches")
    parser.add_argument("--visualization", action='store_true', help="Export Kibana visualizations")
    parser.add_argument("--dashboard", action='store_true', help="Export Kibana dashboards")
    parser.add_argument("--all", action='store_true', help="Export all Kibana objects (similar to --indexpattern --search --visualizations --dashboards --estemplate)")
    parser.add_argument("--estemplate", action='store_true', help="Export Elasticsearch templates")
    parser.add_argument("--export", action='store_true', help="Export data   (either --export of --process required)")
    parser.add_argument("--process", action='store_true', help="Process locally saved NDJSON files for easy diff   (either --export of --process required)")
    parser.add_argument("--username", metavar="<username>", dest="username", help="Elastic username, if not provided default 'redelk' is used")
    parser.add_argument("--password", metavar="<password>", dest="password", help="Elastic password, if not provided config file ../elkserver/.env will be parsed")

    args = parser.parse_args()

    if not args.indexpattern and not args.search and not args.visualization and not args.dashboard and not args.all and not args.estemplate and not (args.export or args.process):
        print("[X] Missing argument")
        sys.exit(-1)

    if not args.export and not args.process:
        print("[X] Either --export of --process argument required")
        sys.exit(-1)

    return args

if __name__ == '__main__':

    args = check_args()

    global BASE_PATH, KIBANA_USER, KIBANA_PASS

    BASE_PATH = os.path.dirname(os.path.abspath(__file__))

    try:
        f = open(PASSW_FILE, "r")
        for line in f.readlines():
            if 'CREDS_redelk=' in line:
                p = line.split("=")
                PASSW = p[1].strip()
    except:
        print("Error opening password file")

    KIBANA_USER = args.username if args.username else 'redelk'
    
    if args.password:
        KIBANA_PASS = args.password
    else:
        KIBANA_PASS = PASSW

    exportpath = args.exportpath if args.exportpath else os.path.join(BASE_PATH, '../elkserver/docker/redelk-base/redelkinstalldata/templates')
    diff_exportpath = os.path.join(exportpath, DIFF_PATH)
    if not os.path.exists(diff_exportpath):
        os.makedirs(diff_exportpath)

    if (args.indexpattern or args.all):
        if args.export:
            fetch_kibana_object('index-pattern', exportpath)
        if args.process:
            process_kibana_object('index-pattern', exportpath)

    if (args.search or args.all):
        if args.export:
            fetch_kibana_object('search', exportpath)
        if args.process:
            process_kibana_object('search', exportpath)

    if (args.visualization or args.all):
        if args.export:
            fetch_kibana_object('visualization', exportpath)
        if args.process:
            process_kibana_object('visualization', exportpath)

    if (args.dashboard or args.all):
        if args.export:
            fetch_kibana_object('dashboard', exportpath)
        if args.process:
            process_kibana_object('dashboard', exportpath)

    if (args.estemplate or args.all):
        if args.export:
            fetch_es_templates(exportpath)
