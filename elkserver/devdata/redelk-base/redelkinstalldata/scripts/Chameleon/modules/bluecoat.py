import http.server
import json
import re
import socketserver
import sys
import threading
from urllib.parse import urlparse
import time
import traceback
import requests
import os

class NewHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.path = 'webroot/index.html'
        return http.server.SimpleHTTPRequestHandler.do_GET(self)


class ThreadedHTTPServer(object):
    handler = NewHandler

    def __init__(self, host, port):
        self.server = socketserver.TCPServer((host, port), self.handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever)
        self.server_thread.daemon = True

    def start(self):
        self.server_thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


class Bluecoat:
    def __init__(self, url, clonesite):
        self.url = url
        self.clonesite = clonesite
        self.server = ''

    def clone(self):
        print("[-] Cloning " + self.clonesite)
        headers = {'User-Agent': 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)'}
        webContent = requests.get(self.clonesite, headers=headers).content

        if not os.path.exists('webroot'):
            os.makedirs('webroot')

        try:
            if webContent.lower().index(b"<base href=\""):
                pass
        except ValueError:
            parsed_uri = urlparse(self.clonesite)
            base = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)
            webContent = re.sub(b"(<head.*?>)", b"\g<0>\n<base href=\"" + bytes(base, encoding='utf8') + b"\">", webContent, count=1, flags=re.IGNORECASE)

        with open('webroot/index.html', 'wb') as indexFile:
            indexFile.write(webContent)
            indexFile.close()

    def check_category(self):
        # Category checking lifted from CatMyFish
        # https://github.com/Mr-Un1k0d3r/CatMyFish/blob/master/CatMyFish.py
        print("[-] Checking category for " + self.url)

        session = requests.session()
        url = "https://sitereview.bluecoat.com/resource/lookup"
        cookies = {"XSRF-TOKEN": "028e5984-50bf-4c00-ad38-87d19957201a"}
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0",
                         "Accept": "application/json, text/plain, */*", "Accept-Language": "en_US",
                         "Accept-Encoding": "gzip, deflate", "Referer": "https://sitereview.bluecoat.com/",
                         "X-XSRF-TOKEN": "028e5984-50bf-4c00-ad38-87d19957201a",
                         "Content-Type": "application/json; charset=utf-8", "Connection": "close"}
        data = {"captcha": "", "key": "",
                      "phrase": "RXZlbiBpZiB5b3UgYXJlIG5vdCBwYXJ0IG9mIGEgY29tbWVyY2lhbCBvcmdhbml6YXRpb24sIHNjcmlwdGluZyBhZ2FpbnN0IFNpdGUgUmV2aWV3IGlzIHN0aWxsIGFnYWluc3QgdGhlIFRlcm1zIG9mIFNlcnZpY2U=",
                      "source": "new lookup", "url": self.url}
        response = session.post(url, headers=headers, cookies=cookies, json=data)

        try:
            json_data = json.loads(response.content)
            if "errorType" in json_data:
                if json_data["errorType"] == "captcha":
                    print("[-] BlueCoat blocked us :(")
                    return("Blocked by BlueCoat")
                    sys.exit(0)
            category = []
            for entry in json_data["categorization"]:
                category.append(entry["name"])
            cat = ', '.join(category)
            print("\033[1;32m[-] Your site is categorised as: " + cat + "\033[0;0m")
            return(cat)
        except Exception as e:
            traceback.print_exc()

            print("[-] An error occurred")

    def serve_content(self):
        print("[-] Serving content over HTTP server")
        self.server = ThreadedHTTPServer("0.0.0.0", 8000)
        try:
            self.server.start()
        except:
            pass

    def shutdown_server(self):
        print("[-] Shutting down HTTP server")
        self.server.stop()

    def run(self):
        self.clone()
        self.serve_content()
        time.sleep(10)
        self.check_category()
        self.shutdown_server()


if __name__ == "__main__":
    url = sys.argv[1]
    clonesite = sys.argv[2]
    b = Bluecoat(url, clonesite)
    b.clone()
    b.serve_content()
    time.sleep(10)
    b.check_category()
    b.shutdown_server()
