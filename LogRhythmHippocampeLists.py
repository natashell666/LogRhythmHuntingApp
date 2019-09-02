from ThreatIntellProviders.Hippocampe.HippocampeThreatIntel import HippocampeThreatIntel
import argparse
import os
import time


def save_threat_intel(hippo_object, file_name, hippo_type):
    list_file = open(file_name, 'w', encoding='utf-8')
    hippo_values = hippo_object.get_intel_from_type(hippo_type)
    try:
        values = hippo_values[hippo_type]
        for value in values:
            print(str(value.encode('utf-8'), 'utf-8'), file=list_file)
    except KeyError:
        list_file.close()
    list_file.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generic Hippocampe to LogRhythm Threat Intel')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help='Get all the IP in hippocampe', action='store_const', dest='flag', const='ip')
    group.add_argument("--domain", help='Get all the Domains in hippocampe', action='store_const', dest='flag',
                       const='domain')
    group.add_argument("--url", help='Get all the URL\'s in hippocampe', action='store_const', dest='flag', const='url')
    group.add_argument("--all", help='Get all the Threat Intelligence available in anomaly', action='store_const',
                       dest='flag', const='all')

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--api", help='Use the API to send update the lists in LogRhythm', dest='mode',
                            action='store_const', const='api')
    mode_group.add_argument("--list", help='Use the LogRhythm JobMgr Directory to update the lists in LogRhythm',
                            dest='mode', action='store_const', const='list')

    list_group = parser.add_argument_group(title='LogRhythm List options')
    list_group.add_argument("--list_name", help='Name of the file name or list where we will save the intelligence list'
                            , default='hippocampe.lst')
    list_group.add_argument("--list_directory", help='Directory where the Job Manager gets the auto-import lists',
                            default='C:\\Program Files\\LogRhythm\\LogRhythm Job Manager\\config\\list_import')

    api_group = parser.add_argument_group(title='LogRhythm API options')
    api_group.add_argument("--api_key", help='LogRhythm API Key')

    parser.add_argument('--hippo_url', help='Minimum Risk Score to get', default='http://localhost:5000')
    parser.add_argument('--sleep', type=int, help='Time in seconds to wait between requests to Anomali in case of all',
                        default=0)
    parser.add_argument('--debug', type=bool, help='Flag to set the debug On', default=False)

    args = parser.parse_args()

    if args.mode == 'api' and not args.api_key:
        parser.error('The --api argument requires the --api_key parameter set')

    hippocampe = HippocampeThreatIntel(args.hippo_url, debug=args.debug)
    file_path = os.path.join(args.list_directory, args.list_name)

    if args.mode == 'list':
        if args.flag == 'all':
            all_intel_list = ['ip', 'url', 'domain']
            for intel_type in all_intel_list:
                file_convension = 'hippocampe_' + intel_type + '.lst'
                file_path = os.path.join(args.list_directory, file_convension)
                print('Getting ' + intel_type + ' into ' + file_path)
                save_threat_intel(hippocampe, file_path, intel_type)
                time.sleep(args.sleep)
        else:
            save_threat_intel(hippocampe, file_path, args.flag)
