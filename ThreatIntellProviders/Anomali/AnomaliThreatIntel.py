import requests
import urllib.parse
import logging


class AnomaliThreatIntel:
    base_url = 'https://api.threatstream.com'
    investigation_api_url = 'https://api.threatstream.com/api/v2/intelligence/'
    passive_dns_urls = {'domain': 'https://api.threatstream.com/api/v1/pdns/domain/',
                        'ip': 'https://api.threatstream.com/api/v1/pdns/ip/'}
    recorded_future_domain_urls = {'domain': 'https://api.threatstream.com/api/v1/recorded_future/search/domain/',
                                   'ip': 'https://api.threatstream.com/api/v1/recorded_future/search/ip/',
                                   'hash': 'https://api.threatstream.com/api/v1/recorded_future/search/md5/'}
    risk_iq_url = 'https://api.threatstream.com/api/v1/riskiq_ssl/certificate/'

    anomali_global_mapping = {'ip': ['actor_ip', 'actor_ipv6', 'anon_proxy_ipv6', 'anon_vpn', 'anon_vpn_ipv6',
                                     'anon_proxy', 'apt_ip', 'apt_ipv6', 'bot_ip', 'bot_ipv6', 'brute_ip', 'brute_ipv6',
                                     'c2_ip', 'c2_ipv6', 'comm_proxy_ip', 'compromised_ip', 'compromised_ipv6',
                                     'crypto_ip', 'ddos_ip', 'ddos_ipv6', 'exfil_ip', 'exfil_ipv6', 'exploit_ip',
                                     'exploit_ipv6', 'i2p_ip', 'i2p_ipv6', 'mal_ip', 'mal_ipv6', 'p2pcnc',
                                     'p2pcnc_ipv6', 'parked_ip', 'parked_ipv6', 'phish_ip', 'phish_ipv6', 'proxy_ip',
                                     'proxy_ipv6', 'scan_ip', 'scan_ipv6', 'sinkhole_ip', 'sinkhole_ipv6', 'spam_ip',
                                     'spam_ipv6', 'ssh_ip', 'ssh_ipv6', 'suspicious_ip', 'tor_ip', 'tor_ipv6',
                                     'vps_ip', 'vps_ipv6'],
                              'hash': ['apt_md5', 'crypto_hash', 'mal_md5', 'mal_ssdeep', 'mal_sslcert_sh1',
                                       'phish_md5', 'hack_tool', 'apt_ssdeep'],
                              'domain': ['c2_domain', 'comm_proxy_domain', 'compromised_domain',
                                         'disposable_email_domain', 'exfil_domain', 'dyn_dns', 'exploit_domain',
                                         'free_email_domain', 'mal_domain', 'parked_domain', 'phish_domain',
                                         'sinkhole_domain', 'spam_domain', 'suspicious_domain', 'vpn_domain',
                                         'adware_domain', 'apt_domain', 'whois_privacy_domain'],
                              'url': ['apt_url', 'c2_url', 'compromised_url', 'crypto_url', 'exfil_url', 'exploit_url',
                                      'geolocation_url', 'ipcheck_url', 'mal_url', 'parked_url', 'pastesite_url',
                                      'phish_url', 'spam_url', 'speedtest_url', 'suspicious_url',
                                      'torrent_tracker_url'],
                              'service_name': ['apt_service_displayname', 'apt_service_description',
                                               'mal_service_description', 'mal_service_displayname',
                                               'mal_service_name'],
                              'email_address': ['apt_email', 'compromised_email', 'mal_email', 'phish_email',
                                                'spam_email', 'suspicious_email', 'suspicious_reg_email',
                                                'whois_bulk_reg_email', 'whois_privacy_email'],
                              'serial': ['ssl_cert_serial_number'],
                              'process_name': ['apt_file_name', 'mal_file_name'],
                              'process_path': ['apt_file_path', 'mal_file_path'],
                              'user_agent': ['apt_mta', 'apt_ua', 'mal_ua', 'spam_mta'],
                              'subject': ['apt_subject'],
                              'file_path': ['apt_file_path', 'mal_file_path'],
                              'file_name': ['apt_file_name', 'mal_file_name'],
                              'registry_key': ['adware_registry_key', 'apt_registry_key', 'mal_registry_key'],
                              'mutex': ['apt_mutex', 'mal_mutex'],
                              'malware_ip': ['apt_ip', 'apt_ipv6', 'bot_ip', 'bot_ipv6', 'c2_ip', 'c2_ipv6',
                                             'exploit_ip', 'exploit_ipv6', 'mal_ip', 'mal_ipv6', 'p2pcnc',
                                             'p2pcnc_ipv6'],
                              'crytp_ip': ['crypto_ip'],
                              'security_ip': ['actor_ip', 'actor_ipv6', 'brute_ip', 'brute_ipv6', 'compromised_ip',
                                              'compromised_ipv6', 'ddos_ip', 'ddos_ipv6', 'exfil_ip', 'exfil_ipv6',
                                              'i2p_ip', 'i2p_ipv6', 'phish_ip', 'phish_ipv6', 'scan_ip', 'scan_ipv6',
                                              'sinkhole_ip', 'sinkhole_ipv6', 'ssh_ip', 'ssh_ipv6'],
                              'spam_ip': ['phish_ip', 'phish_ipv6', 'spam_ip', 'spam_ipv6'],
                              'ddos_ip': ['ddos_ip', 'ddos_ipv6'],
                              'suspicious_ip': ['parked_ip', 'parked_ipv6', 'suspicious_ip', 'vps_ip', 'vps_ipv6'],
                              'proxy_ip': ['anon_proxy', 'anon_proxy_ipv6', 'comm_proxy_ip', 'proxy_ip', 'proxy_ipv6'],
                              'vpn_ip': ['anon_vpn', 'anon_vpn_ipv6'],
                              'tor_ip': ['tor_ip', 'tor_ipv6'],
                              'malware_domain': ['apt_domain', 'c2_domain', 'exploit_domain', 'mal_domain',
                                                 'adware_domain'],
                              'security_domain': ['compromised_domain', 'exfil_domain', 'exploit_domain',
                                                  'sinkhole_domain', 'adware_domain'],
                              'spam_domain': ['disposable_email_domain', 'free_email_domain', 'phish_domain',
                                              'spam_domain'],
                              'suspicious_domain': ['compromised_domain', 'disposable_email_domain', 'exfil_domain',
                                                    'dyn_dns', 'free_email_domain', 'parked_domain',
                                                    'suspicious_domain', 'whois_privacy_domain'],
                              'proxy_domain': ['comm_proxy_domain'],
                              'vpn_domain': ['vpn_domain'],
                              'adware_domain': ['adware_domain']}

    def __init__(self, api_username, api_key, search_limit=10000, debug=False):
        self.api_username = api_username
        self.api_key = api_key
        self.search_limit = search_limit
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

    def create_anomali_query(self, query_type):
        if self.anomali_global_mapping[query_type] is None:
            raise Exception('Wrong intel type passed as argument to Anomali')
        anomali_map = self.anomali_global_mapping[query_type]
        complex_query = ''
        counter = 0
        for mapping in anomali_map:
            counter = counter + 1
            complex_query = complex_query + 'itype="' + mapping + '"'
            if counter < len(anomali_map):
                complex_query = complex_query + '+OR+'
        return complex_query

    def get_intel_type(self, intel_type, confidence_min_level=0, status=False):
        query_string = ''
        if status is False:
            query_string = '?username={0}&api_key={1}&limit={2}&' \
                           'order_by=update_id&' \
                           'q=(confidence>={3}+AND+({4}))'.format(self.api_username, self.api_key,
                                                                  self.search_limit,
                                                                  confidence_min_level,
                                                                  self.create_anomali_query(intel_type))
        else:
            query_string = '?username={0}&api_key={1}&limit={2}&status=active&' \
                           'order_by=update_id&' \
                           'q=(confidence>={3}+AND+({4}))'.format(self.api_username, self.api_key,
                                                                  self.search_limit,
                                                                  confidence_min_level,
                                                                  self.create_anomali_query(intel_type))

        anomali_url = urllib.parse.urljoin(self.investigation_api_url, query_string)
        anomali_response = requests.get(anomali_url, headers={'ACCEPT': 'application/json, text/html'})
        anomali_objects = []
        print(anomali_url)
        offset = self.search_limit
        if anomali_response.status_code == 200:
            anomali_objects = anomali_response.json()['objects']
            while anomali_response.json()['meta']['next'] is not None and offset < 100000:
                offset = offset + 1000
                new_query_url = urllib.parse.urljoin(self.investigation_api_url,
                                                     anomali_response.json()['meta']['next'])
                anomali_response = requests.get(new_query_url, headers={'ACCEPT': 'application/json, text/html'})
                if anomali_response.status_code == 200:
                    anomali_objects = anomali_objects + anomali_response.json()['objects']

        return anomali_objects

    def get_intel_detail(self, intel_value):
        query_string = '?username={0}&api_key={1}&limit={2}&value={3}'.format(self.api_username, self.api_key,
                                                                              self.search_limit, intel_value)
        anomali_url = urllib.parse.urljoin(self.investigation_api_url, query_string)
        anomali_response = requests.get(anomali_url, headers={'ACCEPT': 'application/json, text/html'})
        anomali_objects = []
        if anomali_response.status_code == 200:
            anomali_objects = anomali_response.json()['objects']
            while anomali_response.json()['meta']['next'] is not None:
                new_query_url = urllib.parse.urljoin(self.investigation_api_url,
                                                     anomali_response.json()['meta']['next'])
                anomali_response = requests.get(new_query_url, headers={'ACCEPT': 'application/json, text/html'})
                if anomali_response.status_code == 200:
                    anomali_objects = anomali_objects + anomali_response.json()['objects']

        return anomali_objects

    def get_passive_dns_details(self, intel_value, intel_type='domain'):
        query_string = '{0}/?username={1}&api_key={2}'.format(intel_value, self.api_username, self.api_key)
        if self.passive_dns_urls[intel_type] is None:
            raise Exception('The Intel type: {} is not valid'.format(intel_type))
        anomali_url = urllib.parse.urljoin(self.passive_dns_urls[intel_type], query_string)
        anomali_response = requests.get(anomali_url, headers={'ACCEPT': 'application/json, text/html'})
        anomali_results = []
        if anomali_response.status_code == 200 and anomali_response.json()['success'] is True:
            anomali_results = anomali_response.json()['results']

        return anomali_results

    def get_recorded_future_details(self, intel_value, intel_type='domain'):
        query_string = '{0}/?username={1}&api_key={2}'.format(intel_value, self.api_username, self.api_key)
        if self.recorded_future_domain_urls[intel_type] is None:
            raise Exception('The Intel type: {} is not valid'.format(intel_type))
        anomali_url = urllib.parse.urljoin(self.recorded_future_domain_urls[intel_type], query_string)
        anomali_response = requests.get(anomali_url, headers={'ACCEPT': 'application/json, text/html'})
        anomali_results = []
        if anomali_response.status_code == 200 and anomali_response.json()['success'] is True:
            anomali_results = anomali_response.json()['results']

        return anomali_results

    def get_risk_iq_details(self, intel_value):
        query_string = '{0}/?username={1}&api_key={2}'.format(intel_value, self.api_username, self.api_key)
        anomali_url = urllib.parse.urljoin(self.risk_iq_url, query_string)
        anomali_response = requests.get(anomali_url, headers={'ACCEPT': 'application/json, text/html'})
        anomali_results = []
        if anomali_response.status_code == 200 and anomali_response.json()['success'] is True:
            anomali_results = anomali_response.json()['results']

        return anomali_results


if __name__ == '__main__':
    anomali = AnomaliThreatIntel('natas@natas.com', 'ffffffffffffffff')
    anomali.get_intel_type('user_agent')
