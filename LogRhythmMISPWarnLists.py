import traceback
import argparse
import os
from ListProviders.LogRhythm.LogRhythmListManagement import LogRhythmListManagement
from ThreatIntellProviders.MISP.MISPThreatIntel import MISPThreatIntel
from ThreatIntellProviders.MISP.MISPThreatIntel import WarnListFilter


lr_list_misp_mapping = {'authentihash': 'MISP WarnList: Hashes', 'cdhash': 'MISP WarnList: Hashes',
                        'domain': 'MISP WarnList: Domains',
                        'email-dst': 'MISP WarnList: Destination Address',
                        'email-reply-to': 'MISP WarnList: Email Address',
                        'email-src': 'MISP WarnList: Email Address', 'email-subject': 'MISP WarnList: Subjects',
                        'filename': 'MISP WarnList: Filenames', 'impfuzzy': 'MISP WarnList: Hashes',
                        'imphash': 'MISP WarnList: Hashes', 'md5': 'MISP WarnList: Hashes',
                        'pehash': 'MISP WarnList: Hashes', 'sha1': 'MISP WarnList: Hashes',
                        'sha224': 'MISP WarnList: Hashes', 'sha256': 'MISP WarnList: Hashes',
                        'sha384': 'MISP WarnList: Hashes', 'sha512': 'MISP WarnList: Hashes',
                        'sha512/224': 'MISP WarnList: Hashes', 'sha512/256': 'MISP WarnList: Hashes',
                        'ssdeep': 'MISP WarnList: Hashes', 'tlsh': 'MISP WarnList: Hashes',
                        'hassh-md5': 'MISP WarnList: Hashes', 'hasshserver-md5': 'MISP WarnList: Hashes',
                        'ja3-fingerprint-md5': 'MISP WarnList: Hashes', 'hostname': 'MISP WarnList: Domains',
                        'ip-dst': 'MISP WarnList: Destination Address', 'ip-src': 'MISP WarnList: Source Address',
                        'link': 'MISP WarnList: URL', 'mime-type': 'MISP WarnList: Mime Type',
                        'mutex': 'MISP WarnList: Mutex', 'named pipe': 'MISP WarnList: Named Pipes',
                        'regkey': 'MISP WarnList: Registry Keys', 'target-email': 'MISP WarnList: Email Address',
                        'target-machine': 'MISP WarnList: Domains', 'target-user': 'MISP WarnList: Users',
                        'uri': 'MISP WarnList: URL', 'url': 'MISP WarnList: URL',
                        'user-agent': 'MISP WarnList: User Agent', 'vulnerability': 'MISP WarnList: Vulnerability',
                        'windows-scheduled-task': 'MISP WarnList: Process',
                        'windows-service-name': 'MISP WarnList: Process',
                        'windows-service-displayname': 'MISP WarnList: Process'}

lr_list_to_data_type = {'MISP WarnList: Hashes': 'String', 'MISP WarnList: Domains': 'String',
                        'MISP WarnList: Email Address': 'String', 'MISP WarnList: Filenames': 'String',
                        'MISP WarnList: Mime Type': 'String', 'MISP WarnList: Subjects': 'String',
                        'MISP WarnList: URL': 'String', 'MISP WarnList: Mutex': 'String',
                        'MISP WarnList: Named Pipes': 'String', 'MISP WarnList: Registry Keys': 'String',
                        'MISP WarnList: Vulnerability': 'String', 'MISP WarnList: Process': 'String',
                        'MISP WarnList: Destination Address': 'IP', 'MISP WarnList: Source Address': 'IP',
                        'MISP WarnList: Users': 'String', 'MISP WarnList: User Agent': 'String'}

lr_list_to_item_type = {'MISP WarnList: Hashes': 'StringValue', 'MISP WarnList: Domains': 'StringValue',
                        'MISP WarnList: Email Address': 'StringValue', 'MISP WarnList: Filenames': 'StringValue',
                        'MISP WarnList: Mime Type': 'StringValue', 'MISP WarnList: Subjects': 'StringValue',
                        'MISP WarnList: URL': 'StringValue', 'MISP WarnList: Mutex': 'StringValue',
                        'MISP WarnList: Named Pipes': 'StringValue', 'MISP WarnList: Registry Keys': 'StringValue',
                        'MISP WarnList: Vulnerability': 'StringValue', 'MISP WarnList: Process': 'StringValue',
                        'MISP WarnList: Destination Address': 'IP', 'MISP WarnList: Source Address': 'IP',
                        'MISP WarnList: Users': 'StringValue', 'MISP WarnList: User Agent': 'StringValue'}

lr_list_name_to_list_type = {'MISP WarnList: Hashes': 'GeneralValue', 'MISP WarnList: Domains': 'GeneralValue',
                             'MISP WarnList: Email Address': 'GeneralValue', 'MISP WarnList: Filenames': 'GeneralValue',
                             'MISP WarnList: Mime Type': 'GeneralValue', 'MISP WarnList: Subjects': 'GeneralValue',
                             'MISP WarnList: URL': 'GeneralValue', 'MISP WarnList: Mutex': 'GeneralValue',
                             'MISP WarnList: Named Pipes': 'GeneralValue', 'MISP WarnList: Registry Keys': 'GeneralValue',
                             'MISP WarnList: Vulnerability': 'GeneralValue', 'MISP WarnList: Process': 'GeneralValue',
                             'MISP WarnList: Destination Address': 'IP', 'MISP WarnList: Source Address': 'IP',
                             'MISP WarnList: Users': 'User', 'MISP WarnList: User Agent': 'GeneralValue'}

lr_list_name_to_context = {'MISP WarnList: Hashes': ['Hash', 'Object'],
                           'MISP WarnList: Domains': ['DomainImpacted', 'HostName', 'DomainOrigin'],
                           'MISP WarnList: Email Address': ['Address'],
                           'MISP WarnList: Filenames': ['Object', 'ObjectName'],
                           'MISP WarnList: Mime Type': ['Object', 'ObjectName'],
                           'MISP WarnList: Subjects': ['Subject'],
                           'MISP WarnList: URL': ['URL'],
                           'MISP WarnList: Mutex': ['Object', 'ParentProcessName', 'Process', 'ObjectName'],
                           'MISP WarnList: Named Pipes': ['Object', 'ParentProcessName', 'Process', 'ObjectName'],
                           'MISP WarnList: Registry Keys': ['Object', 'ObjectName'],
                           'MISP WarnList: Vulnerability': ['Object', 'CVE'],
                           'MISP WarnList: Process': ['Object', 'ParentProcessName', 'Process', 'ObjectName'],
                           'MISP WarnList: User Agent': ['UserAgent']}


def save_intel_to_file(misp_object, _file_name):
    list_file = open(_file_name, 'w', encoding='utf-8')
    for value in misp_object:
        print(str(value.encode('utf-8'), 'utf-8'), file=list_file)
    list_file.close()


def save_intel_to_lr_list(misp_object, lr_api_gw, lr_api_key, list_name):
    list_api = LogRhythmListManagement(lr_api_gw, lr_api_key)
    warn_lists = list_api.get_lists_summary(list_name=list_name)
    if warn_lists is None or len(warn_lists) < 1:
        if list_name == 'MISP WarnList: Destination Address' or list_name == 'MISP WarnList: Source Address' or \
                list_name == 'MISP WarnList: Users':
            lst_context = None
        else:
            lst_context = lr_list_name_to_context[list_name]

        warn_lists = []
        warn_tmp = list_api.create_list(list_name, list_type=lr_list_name_to_list_type[list_name],
                                        use_context=lst_context)
        warn_lists.append(warn_tmp)

        if len(warn_lists) > 0:
            guid = warn_lists[0]['guid']
            for item in misp_object:
                try:
                    list_api.insert_item(guid, item, item, list_item_data=lr_list_to_data_type[list_name],
                                         list_item_type=lr_list_to_item_type[list_name])
                except Exception as e:
                    print('Error adding the item: ' + str(item))
                    traceback.print_exc()


class WarnList:
    def __init__(self, misp_url, misp_key, misp_verifycert=False, debug=False):
        self.misp_intel = MISPThreatIntel(misp_url, misp_key, misp_verifycert, debug)

    def process_warn_list(self, list_id: int):
        warn_items = self.misp_intel.get_warnlist_items(list_id)
        warn_values = list()
        for item in warn_items:
            warn_values.append(item['value'])
        return warn_values

    def get_list_for_id(self, list_id: int):
        list_name = None
        warn_lists = self.misp_intel.get_warnlists(WarnListFilter.All)
        for item in warn_lists:
            if str(list_id) == item['Warninglist']['id']:
                s_attrs = item['Warninglist']['valid_attributes']
                attrs = s_attrs.split(',')
                if len(attrs) < 1:
                    continue
                for attr in attrs:
                    if attr.strip() in lr_list_misp_mapping:
                        list_name = lr_list_misp_mapping[attr.strip()]
                        break
        return list_name

    def get_lists(self, enabled: WarnListFilter = WarnListFilter.Enabled):
        warn_lists = self.misp_intel.get_warnlists(enabled)
        return_list = list()
        for item in warn_lists:
            s_attrs = item['Warninglist']['valid_attributes']
            attrs = s_attrs.split(',')
            id = item['Warninglist']['id']
            list_name = None
            if len(attrs) < 1:
                continue
            for attr in attrs:
                if attr.strip() in lr_list_misp_mapping:
                    list_name = lr_list_misp_mapping[attr.strip()]
                    break
            if list_name is None:
                continue
            list_value = {'list': list_name, 'id': id}
            return_list.append(list_value)
        return return_list


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Saves WarnLists into LogRhythm Threat Lists')

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--lr_api", help='Use the API to send update the lists in LogRhythm', dest='mode',
                            action='store_const', const='api')
    mode_group.add_argument("--lr_list", help='Use the LogRhythm JobMgr Directory to update the lists in LogRhythm',
                            dest='mode', action='store_const', const='list')

    list_group = parser.add_argument_group(title='LogRhythm List options')
    list_group.add_argument("--lr_list_directory", help='Directory where the Job Manager gets the auto-import lists',
                            default='C:\\Program Files\\LogRhythm\\LogRhythm Job Manager\\config\\list_import')

    api_group = parser.add_argument_group(title='LogRhythm API options')
    api_group.add_argument("--lr_api_key", help='LogRhythm API Key')
    api_group.add_argument("--lr_api_gw", help='LogRhythm API Gateway Host', default='https://localhost:8505')

    parser.add_argument('--misp_url', help='MISP Url', default='https://localhost/')
    parser.add_argument('--misp_key', help='MISP API Key', required=True)
    parser.add_argument('--disabled', type=bool, help='Flag to get disabled Lists as well', default=False)
    parser.add_argument('--list_id', type=int, help='Gets only the specified ID, by defaults gets all the lists',
                        default=-1)
    parser.add_argument('--debug', type=bool, help='Flag to set the debug On', default=False)

    args = parser.parse_args()

    if args.mode == 'api' and not args.lr_api_key:
        parser.error('The --api argument requires the --lr_api_key parameter set')

    api = WarnList(args.misp_url, args.misp_key, misp_verifycert=False, debug=False)

    if args.list_id == -1:
        lists = []
        if args.disabled:
            lists = api.get_lists(enabled=WarnListFilter.All)
        else:
            lists = api.get_lists(enabled=WarnListFilter.Enabled)
        for _list in lists:
            lists_items = api.process_warn_list(_list['id'])
            if args.mode == 'api':
                save_intel_to_lr_list(lists_items, args.lr_api_gw, args.lr_api_key, _list['list'])
            else:
                file_name = _list['list'].replace(": ", " - ") + '.lst'
                file_path = os.path.join(args.lr_list_directory, file_name)
                save_intel_to_file(lists_items, file_path)
    else:
        lists_items = api.process_warn_list(args.list_id)
        if args.mode == 'api':
            save_intel_to_lr_list(lists_items, args.lr_api_gw, args.lr_api_key, api.get_list_for_id(args.list_id))
        else:
            file_name = api.get_list_for_id(args.list_id).replace(": ", " - ") + '.lst'
            file_path = os.path.join(args.lr_list_directory, file_name)
