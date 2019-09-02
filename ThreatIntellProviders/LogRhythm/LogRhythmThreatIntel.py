import requests
import urllib.parse
import logging


class LogRhythmThreatIntel:
    def __init__(self, base_url, api_key, debug=False):
        self.base_url = base_url
        self.api_key = api_key
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

    def get_lt_threat_intelligence(self, ioc):
        logrhythm_uri = 'observables/actions/search'
        logrhythm_threat_url = urllib.parse.urljoin(self.base_url, logrhythm_uri)
        logrhythm_search = {'value': ioc}
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_response = requests.post(logrhythm_threat_url, json=logrhythm_search, headers=logrhythm_headers,
                                           verify=False)
        if logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Threat Intelligence didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))
        return logrhythm_response.json()

    def get_lt_threat_intelligence_context(self, ioc, provider):
        logrhythm_provider_url = 'providers/' + provider + '/actions/search'
        logrhythm_threat_url = urllib.parse.urljoin(self.base_url, logrhythm_provider_url)
        logrhythm_search = {'value': ioc}
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_response = requests.post(logrhythm_threat_url, json=logrhythm_search, headers=logrhythm_headers,
                                           verify=False)
        if logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Threat Intelligence didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))
        return logrhythm_response.json()
