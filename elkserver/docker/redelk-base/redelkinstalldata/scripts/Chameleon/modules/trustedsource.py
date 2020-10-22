import requests
import sys
import time
import urllib.request, urllib.parse, urllib.error
from bs4 import BeautifulSoup


class TrustedSource:
    def __init__(self, url):
        self.url = url

    def check_category(self, submit):
        print("[-] Getting anti-automation tokens")
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5'
        }
        session.headers.update(headers)
        base_check = 'http://www.trustedsource.org/sources/index.pl'
        r = session.get(base_check)
        bs = BeautifulSoup(r.text, "html.parser")
        form = bs.find("form", {"class": "contactForm"})
        e = form.find("input", {'name': 'e'}).get('value')
        c = form.find("input", {'name': 'c'}).get('value')

        print("[-] Checking category for " + self.url)
        headers['Referer'] = base_check
        session.headers.update(headers)
        payload = {'sid': (None, ''), 'e': (None, e), 'c': (None, c), 'p': (None, ''), 'action': (None, 'checksingle'),
                   'product': (None, '13-ts-3'), 'url': (None, self.url)}
        response = session.post('https://www.trustedsource.org/en/feedback/url', headers=headers, files=payload)
        bs = BeautifulSoup(response.content, "html.parser")
        form = bs.find("form", {"class": "contactForm"})
        sid = form.find("input", {'name': 'sid'}).get('value')
        results_table = bs.find("table", {"class": "result-table"})
        td = results_table.find_all('td')
        print("\033[1;32m[-] Found category: " + td[len(td) - 2].text + "\033[0;0m")

        if submit:
            self.submit_category(sid)
        
        return(td[len(td) - 2].text)

    def submit_category(self, sid):
        print("[-] Submitting URL for finance category")
        post_data = {
            'sid': sid,
            'p': '',
            'action': 'feedback',
            'cat_1': 'fi',
            'cat_2': 'fi',
            'cat_3': 'fi',
            'comment': '',
            'result': 'Submit+URL+for+Review'
        }
        headers = {
            'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-GB,en;q=0.5',
            'Referer': 'https://www.trustedsource.org/en/feedback/url',
            'DNT': '1'
        }
        response = requests.post('https://www.trustedsource.org/en/feedback/url', data=post_data, headers=headers)
        if b"Thank you for your URL feedback" in response.content:
            print("[-] URL submitted, please wait up to 6 hours for categorisation")
        else:
            "[-] An error occured in URL submission"


if __name__ == "__main__":
    url = sys.argv[1]
    ts = TrustedSource(url)
    ts.check_category(True)