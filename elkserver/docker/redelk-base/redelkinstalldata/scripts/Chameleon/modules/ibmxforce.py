import sys
import json
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class IBMXforce:

    def __init__(self, domain):
        self.domain = domain
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

    # In part ripped from DomainHunter
    # https://github.com/minisllc/domainhunter/blob/master/domainhunter.py
    # Credit: Joe Vest and Andrew Chiles
    def checkIBMxForce(self):
        print(('[-] IBM xForce Check: {}'.format(self.domain)))
        s = requests.Session()
        useragent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0'
        try:
            url = 'https://exchange.xforce.ibmcloud.com/api/url/{}'.format(
                self.domain)
            headers = {
                'User-Agent': useragent,
                'Accept': 'application/json, text/plain, */*',
                'Accept-Language': 'en-GB,en;q=0.5',
                'x-ui': 'XFE',
                'Referer': "https://exchange.xforce.ibmcloud.com/url/{}".format(self.domain),
                'Connection': 'close'
            }
            response = s.get(url, headers=headers, verify=False)

            if response.status_code == 404:
                print('[-] IBM x-Force does not have entries for the domain!')
                return "No reputation known"

            responseJson = json.loads(response.text)
            parsedJson = "{}".format(" | ".join(list(responseJson["result"].get('cats', {}).keys())))
            print("\033[1;32m[-] Domain categorised as " + parsedJson + "\033[0;0m")
            return(parsedJson)
            
        except Exception as e:            
            print('[-] Error retrieving IBM x-Force reputation!')
            return "Error getting reputation"

    def submit_category(self):
        print(('[-] Submitting {} for Financial category'.format(self.domain)))
        s = requests.Session()
        useragent = 'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)'
        url = 'https://exchange.xforce.ibmcloud.com/url/{}'.format(self.domain)
        headers = {'User-Agent': useragent,
                   'Accept': 'application/json, text/plain, */*',
                   'x-ui': 'XFE',
                   'Origin': url,
                   'Referer': url,
                   'Content-Type': 'application/json;charset=utf-8'}
        post_data = "{\"feedback\":{\"sourceid\":\"%s\",\"feedbacktext\":\"\",\"current\":{\"urlcategory\":[]},\"proposed\":{\"urlcategory\":[{\"name\":\"Banking\",\"action\":\"ADD\",\"id\":\"53\"}]},\"webApplication\":\"\",\"notify\":true,\"postAsComment\":true}}" % self.domain

        url = 'https://exchange.xforce.ibmcloud.com/api/url/feedback/{}'.format(
            self.domain)
        response = s.post(url, data=post_data, headers=headers)
        if b"Thank you for your time and feedback" in response.content:
            print("[-] Category successfully submitted, please wait an hour")
        else:
            print("[-] Error submitting category")

if __name__ == "__main__":
    url = sys.argv[1]
    xf = IBMXforce(url)
    xf.checkIBMxForce()
    xf.submit_category()
