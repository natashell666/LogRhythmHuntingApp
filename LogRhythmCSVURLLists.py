from ThreatIntellProviders.Misc.GetCSVListIntel import URLCSVThreatIntel
from ListProviders.LogRhythm.LogRhythmListManagement import LogRhythmListManagement
import argparse
import os
import time


def save_threat_intel(csv_list, file_name):
    list_file = open(file_name, 'w', encoding='utf-8')
    for value in csv_list:
        print(str(value['value'].encode("utf-8"), 'utf-8'), file=list_file)
    list_file.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generic CSV from URL to LogRhythm Threat Intel')
    parser.add_argument('--debug', action='store_true', help='Print debug info', default=False)
    parser.add_argument('csv_url', help='URL where the CSV file is located')
    parser.add_argument('--field', help='Column number where the item must be taken', type=int, default=0)
    parser.add_argument('--ignore', help='Ignore CSV lines starting with this string', default='#')

    subparsers = parser.add_subparsers(dest='mode', help='list or api should be set as mode', required=True)
    list_parser = subparsers.add_parser('list', help='Save the ThreatList into a file')
    api_parser = subparsers.add_parser('api', help='Save the ThreatList directly into LogRhythm using the API')

    list_parser.add_argument("--list_directory", help='Directory where the Job Manager gets the auto-import lists',
                             default='C:\\Program Files\\LogRhythm\\LogRhythm Job Manager\\config\\list_import')
    list_parser.add_argument("--list_name", help='Name of the filename or list where we will save the intelligence '
                                                 'list, ex.: dga.lst', required=True)

    api_parser.add_argument("--api_url", help='URL Of the LogRhythm API Gateway, ex: https://localhost:8501',
                            default='https://localhost:8501')
    api_parser.add_argument("--api_key", help='API Key for connecting to LogRhythm API Gateway', required=True)
    list_parser.add_argument("--list_name", help='Name of the LogRhythm List to update', required=True)


    args = parser.parse_args()
    url_cvs = URLCSVThreatIntel(args.csv_url, csv_field=args.field, ignore_start_with=args.ignore, debug=args.debug)
    threat_list = url_cvs.get_csv_threat_intel()
    if args.mode == 'list':
        file_path = os.path.join(args.list_directory, args.list_name)
        save_threat_intel(threat_list, file_path)
    elif args.mode == 'api':
        lr_api = LogRhythmListManagement(args.api_url, args.api_key, debug=args.debug)


