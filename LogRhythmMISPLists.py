from ThreatIntellProviders.MISP.MISPThreatIntel import MISPThreatIntel
from ThreatIntellProviders.MISP.MISPThreatIntel import WarnListFilter
import argparse
import os
import time


def save_threat_intel(misp_object, file_name, misp_type):
    list_file = open(file_name, 'w', encoding='utf-8')
    misp_values = misp_object.get_intel_from_type(misp_type)
    try:
        values = misp_values[misp_type]
        for value in values:
            print(str(value.encode('utf-8'), 'utf-8'), file=list_file)
    except KeyError:
        list_file.close()
    list_file.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generic MISP Threat Intelligence into LogRhythm Threat Lists')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help='Get all the IP in mispcampe', action='store_const', dest='flag', const='ip')
    group.add_argument("--domain", help='Get all the Domains in mispcampe', action='store_const', dest='flag',
                       const='domain')
    group.add_argument("--url", help='Get all the URL\'s in mispcampe', action='store_const', dest='flag', const='url')
    group.add_argument("--all", help='Get all the Threat Intelligence available in anomaly', action='store_const',
                       dest='flag', const='all')

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--api", help='Use the API to send update the lists in LogRhythm', dest='mode',
                            action='store_const', const='api')
    mode_group.add_argument("--list", help='Use the LogRhythm JobMgr Directory to update the lists in LogRhythm',
                            dest='mode', action='store_const', const='list')

    list_group = parser.add_argument_group(title='LogRhythm List options')
    list_group.add_argument("--list_name", help='Name of the file name or list where we will save the intelligence list'
                            , default='mispcampe.lst')
    list_group.add_argument("--list_directory", help='Directory where the Job Manager gets the auto-import lists',
                            default='C:\\Program Files\\LogRhythm\\LogRhythm Job Manager\\config\\list_import')

    api_group = parser.add_argument_group(title='LogRhythm API options')
    api_group.add_argument("--api_key", help='LogRhythm API Key')

    parser.add_argument('--misp_url', help='Minimum Risk Score to get', default='http://localhost:5000')
    parser.add_argument('--sleep', type=int, help='Time in seconds to wait between requests to Anomali in case of all',
                        default=0)
    parser.add_argument('--debug', type=bool, help='Flag to set the debug On', default=False)

    args = parser.parse_args()

    if args.mode == 'api' and not args.api_key:
        parser.error('The --api argument requires the --api_key parameter set')
