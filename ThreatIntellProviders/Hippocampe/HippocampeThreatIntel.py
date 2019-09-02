import requests
import urllib.parse
import logging


class HippocampeThreatIntel:
    hippocampe_uris = {'query': '/hippocampe/api/v1.0/distinct',
                       'score': '/hippocampe/api/v1.0/hipposcore',
                       'intel': '/hippocampe/api/v1.0/more',
                       'type': '/hippocampe/api/v1.0/type'}
    hippocampe_valid_types = {'ip': 'ip', 'url': 'url', 'domain': 'domain'}

    def __init__(self, base_url, debug=False):
        self.base_url = base_url
        if debug:
            try:
                import http.client as http_client
            except ImportError:
                # Python 2
                import httplib as http_client
                http_client.HTTPConnection.debuglevel = 1

            # You must initialize logging, otherwise you'll not see debug output.
            logging.basicConfig()
            logging.getLogger().setLevel(logging.DEBUG)
            requests_log = logging.getLogger("requests.packages.urllib3")
            requests_log.setLevel(logging.DEBUG)
            requests_log.propagate = True

    def get_intel_from_type(self, intel_type):
        if self.hippocampe_valid_types[intel_type] is None:
            raise Exception('Wrong intel type passed as argument to Hippocampe')

        hippo_query = {"field": [intel_type]}
        hippo_url = urllib.parse.urljoin(self.base_url, self.hippocampe_uris['query'])

        hippo_response = requests.post(hippo_url, json=hippo_query, headers={'Content-Type': 'application/json'},
                                       verify=False)
        if hippo_response.status_code != 200:
            raise Exception('Hippocampe is not fully available: {}'.format(hippo_response.status_code))
        return hippo_response.json()

    def get_intel_score(self, intel_type, intel_value):
        if self.hippocampe_valid_types[intel_type] is None:
            raise Exception('Wrong intel type passed as argument to Hippocampe')

        hippo_query = {intel_value: {"type": intel_type}}
        hippo_url = urllib.parse.urljoin(self.base_url, self.hippocampe_uris['score'])

        hippo_response = requests.post(hippo_url, json=hippo_query, headers={'Content-Type': 'application/json'},
                                       verify=False)
        if hippo_response.status_code != 200:
            raise Exception('Hippocampe is not fully available: {}'.format(hippo_response.status_code))
        return hippo_response.json()

    def get_intel_detail(self, intel_type, intel_value):
        if self.hippocampe_valid_types[intel_type] is None:
            raise Exception('Wrong intel type passed as argument to Hippocampe')

        hippo_query = {intel_value: {'type': intel_type}}
        hippo_url = urllib.parse.urljoin(self.base_url, self.hippocampe_uris['intel'])

        hippo_response = requests.post(hippo_url, json=hippo_query, headers={'Content-Type': 'application/json'},
                                       verify=False)

        if hippo_response.status_code != 200:
            raise Exception('Hippocampe is not fully available: {}'.format(hippo_response.status_code))
        return hippo_response.json()


if __name__ == '__main__':
    hippocampe = HippocampeThreatIntel('http://hermes.natashell.me:5500')
    # print(hippocampe.get_intel_detail('ip', '185.156.177.79'))
    hippo_response = hippocampe.get_intel_from_type('url')
    try:
        domains = hippo_response['url']
        for domain in domains:
            print(str(domain.encode('utf-8'), 'utf-8'))
    except KeyError:
        print('Hippocampe didn\'t return values')
