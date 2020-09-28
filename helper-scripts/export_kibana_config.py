import ndjson
import json
import requests
import re
import argparse
import sys
from pprint import pprint

# Quick hack to disable invalid cert warning
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

KIBANA_URL = 'https://localhost:5601'
KIBANA_USER = 'redelk'
KIBANA_PASS = 'redelk'
KIBANA_OBJECTS_EXPORT_URL = KIBANA_URL + '/api/saved_objects/_export'
REDELK_OBJ_FILTER = 'RedELK'
INDEX_PATTERNS_FILTER = 'rtops|redirtraffic|implantsdb|bluecheck|credentials|email|.siem-signals'
EXPORT_FILES_PREFIX_KIBANA = 'redelk_kibana_'
ES_URL = 'https://localhost:9200'
ES_TEMPLATES_LIST = [ 'rtops', 'redirtraffic', 'implantsdb' ]
EXPORT_FILES_PREFIX_ES = 'redelk_elasticsearch_'
DIFF_PATH = 'diff/' # path is relative to exportpath


def fetch_kibana_object(obj_type, exportpath):
    print('# Processing kibana objects: %s' % obj_type)
    response = requests.post(KIBANA_OBJECTS_EXPORT_URL, json={'type':obj_type}, verify=False, auth=(KIBANA_USER,KIBANA_PASS), headers={'kbn-xsrf':'true'})
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
        print('Exporting %s: %s%s%s.ndjson' % (obj_type,exportpath,EXPORT_FILES_PREFIX_KIBANA,obj_type))
        with open('%s%s%s.ndjson' % (exportpath,EXPORT_FILES_PREFIX_KIBANA,obj_type), 'w') as f:
            ndjson.dump(toExport, f)
    else:
        for ip in items:
            if 'attributes' in ip.keys() and 'title' in ip['attributes']:
                if re.match(INDEX_PATTERNS_FILTER, ip['attributes']['title'], re.IGNORECASE):
                    # print('%s: %s' % (obj_type,ip['attributes']['title']))
                    pn = ip['attributes']['title'][:-2] if ip['attributes']['title'].endswith('-*') else ip['attributes']['title']
                    ip.pop('updated_at', None)
                    ip['version'] = '1'
                    print('Exporting %s: %s%s%s_%s.ndjson' % (obj_type,exportpath,EXPORT_FILES_PREFIX_KIBANA,obj_type,pn))
                    with open('%s%s%s_%s.ndjson' % (exportpath,EXPORT_FILES_PREFIX_KIBANA,obj_type,pn), 'w') as f:
                        ndjson.dump([ip], f)

def fetch_es_templates(exportpath):
    for i in ES_TEMPLATES_LIST:
        print('# Processing ES template: %s' % i)
        response = requests.get('%s/_template/%s' % (ES_URL, i), verify=False, auth=(KIBANA_USER,KIBANA_PASS))
        rawData = response.text.encode('utf-8')
        tmpl = json.loads(rawData)
        print('Exporting index template %s: %s%stemplate_%s.json' % (i,exportpath,EXPORT_FILES_PREFIX_ES,i))
        with open('%s%stemplate_%s.json' % (exportpath,EXPORT_FILES_PREFIX_ES,i), 'w') as f:
            json.dump(tmpl[i], f, indent=4, sort_keys=True)

def process_kibana_object(obj_type, exportpath, indexpattern=None):
    print('# Processing kibana objects: %s' % obj_type)

    if obj_type != 'index-pattern':
        src_file = '%s%s' % (EXPORT_FILES_PREFIX_KIBANA, obj_type)
    else:
        if indexpattern is None:
            for i in INDEX_PATTERNS_FILTER.split('|'):
                process_kibana_object(obj_type, exportpath, indexpattern=i)
            return
        else:
            src_file = '%s%s_%s' % (EXPORT_FILES_PREFIX_KIBANA, obj_type, indexpattern)

        print('Opening %s: %s%s.ndjson' % (obj_type, exportpath, src_file))
        with open('%s%s.ndjson' % (exportpath, src_file), 'r') as f:
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

        print('Writing output to: %s%s%s.json' % (exportpath, DIFF_PATH, src_file))
        with open('%s%s%s.json' % (exportpath, DIFF_PATH, src_file), 'w') as f:
            json.dump(src_ndjson, f, indent=4, sort_keys=True)

def check_args():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--exportpath", metavar="<exportpath>", dest="exportpath", default='./', help="Path to export the objects (default ./)")
    parser.add_argument("--indexpattern", action='store_true', help="Export Kibana index patterns")
    parser.add_argument("--search", action='store_true', help="Export Kibana searches")
    parser.add_argument("--visualization", action='store_true', help="Export Kibana visualizations")
    parser.add_argument("--dashboard", action='store_true', help="Export Kibana dashboards")
    parser.add_argument("--all", action='store_true', help="Export all Kibana objects (similar to --indexpattern --search --visualizations --dashboards)")
    parser.add_argument("--estemplate", action='store_true', help="Export Elasticsearch templates")
    parser.add_argument("--export", action='store_true', help="Export data")
    parser.add_argument("--process", action='store_true', help="Process NDJSON data (save files for easy diff)")
    args = parser.parse_args()

    if not args.indexpattern and not args.search and not args.visualization and not args.dashboard and not args.all and not args.estemplate and not (args.export or args.process):
        print("[-] Missing argument")
        sys.exit(-1)

    return args

if __name__ == '__main__':

    args = check_args()

    exportpath = args.exportpath if args.exportpath else './'
    diff_exportpath = exportpath + DIFF_PATH

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
