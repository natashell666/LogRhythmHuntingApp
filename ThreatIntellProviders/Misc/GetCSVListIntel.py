import csv
import logging
import requests
from contextlib import closing


class URLCSVThreatIntel:

    def __init__(self, url, csv_field: int = 0, ignore_start_with='#', debug=False):
        self.url = url
        self.csv_field = csv_field
        self.ignore_start_with = ignore_start_with
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

    def get_csv_threat_intel(self):
        csv_threat_intel = list()
        with closing(requests.get(self.url, stream=True)) as r:
            f = (line.decode('utf-8') for line in r.iter_lines())
            reader = csv.reader(f, delimiter=',', quotechar='"')
            i = 0
            for row in reader:
                i = i + 1
                if not row[0].startswith(self.ignore_start_with):
                    csv_threat_intel.append(row[self.csv_field])
        return csv_threat_intel


if __name__ == '__main__':
    csv_url = URLCSVThreatIntel('http://osint.bambenekconsulting.com/feeds/dga-feed.txt')
    ti = csv_url.get_csv_threat_intel()
    print('Len: ' + str(len(ti)))
