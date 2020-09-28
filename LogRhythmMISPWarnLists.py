import traceback
import argparse
import os
from ListProviders.LogRhythm.LogRhythmListManagement import LogRhythmListManagement
from ThreatIntellProviders.MISP.MISPThreatIntel import MISPThreatIntel
from ThreatIntellProviders.MISP.MISPThreatIntel import WarnListFilter


lr_list_misp_mapping = {'authentihash': 'MISP WarnList: Hashes', 'cdhash': 'MISP WarnList: Hashes',
                        'domain': 'MISP WarnList: Domains',
                        'email-dst': 'MISP WarnList: Email Address',
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

misp_attr_to_context = {'authentihash': ['Hash', 'Object'], 'cdhash': ['Hash', 'Object'],
                        'domain': ['DomainImpacted', 'HostName', 'DomainOrigin'], 'email-dst': ['Address'],
                        'email-reply-to': ['Address'], 'email-src': ['Address'], 'email-subject': ['Subject'],
                        'filename': ['Object', 'ObjectName'], 'impfuzzy': ['Hash', 'Object'],
                        'imphash': ['Hash', 'Object'], 'md5': ['Hash', 'Object'], 'pehash': ['Hash', 'Object'],
                        'sha1': ['Hash', 'Object'], 'sha224': ['Hash', 'Object'], 'sha256': ['Hash', 'Object'],
                        'sha384': ['Hash', 'Object'], 'sha512': ['Hash', 'Object'], 'sha512/224': ['Hash', 'Object'],
                        'sha512/256': ['Hash', 'Object'], 'ssdeep': ['Hash', 'Object'], 'tlsh': ['Hash', 'Object'],
                        'hassh-md5': ['Hash', 'Object'], 'hasshserver-md5': ['Hash', 'Object'],
                        'ja3-fingerprint-md5': ['Hash', 'Object'], 'ip-dst': None, 'ip-src': None, 'target-user': None,
                        'hostname': ['DomainImpacted', 'HostName', 'DomainOrigin'],
                        'link': ['URL'], 'mime-type': ['Object', 'ObjectName'],
                        'mutex': ['Object', 'ParentProcessName', 'Process', 'ObjectName'],
                        'named pipe': ['Object', 'ParentProcessName', 'Process', 'ObjectName'],
                        'regkey': ['Object', 'ObjectName'], 'target-email': ['Address'],
                        'target-machine': ['DomainImpacted', 'HostName', 'DomainOrigin'], 'uri': ['URL', 'Object'],
                        'url': ['URL'], 'user-agent': ['UserAgent'], 'vulnerability': ['Object', 'CVE'],
                        'windows-scheduled-task': ['Object', 'ParentProcessName', 'Process', 'ObjectName'],
                        'windows-service-name': ['Object', 'ParentProcessName', 'Process', 'ObjectName'],
                        'windows-service-displayname': ['Object', 'ParentProcessName', 'Process', 'ObjectName']}

misp_attr_to_list_type = {'authentihash': 'GeneralValue', 'cdhash': 'GeneralValue', 'domain': 'GeneralValue',
                          'email-dst': 'GeneralValue', 'email-reply-to': 'GeneralValue', 'email-src': 'GeneralValue',
                          'email-subject': 'GeneralValue', 'filename': 'GeneralValue', 'impfuzzy': 'GeneralValue',
                          'imphash': 'GeneralValue', 'md5': 'GeneralValue', 'pehash': 'GeneralValue',
                          'sha1': 'GeneralValue', 'sha224': 'GeneralValue', 'sha256': 'GeneralValue',
                          'sha384': 'GeneralValue', 'sha512': 'GeneralValue', 'sha512/224': 'GeneralValue',
                          'sha512/256': 'GeneralValue', 'ssdeep': 'GeneralValue', 'tlsh': 'GeneralValue',
                          'hassh-md5': 'GeneralValue', 'hasshserver-md5': 'GeneralValue',
                          'ja3-fingerprint-md5': 'GeneralValue', 'hostname': 'GeneralValue', 'ip-dst': 'IP',
                          'ip-src': 'IP', 'link': 'GeneralValue', 'mime-type': 'GeneralValue', 'mutex': 'GeneralValue',
                          'named pipe': 'GeneralValue', 'regkey': 'GeneralValue', 'target-email': 'GeneralValue',
                          'target-machine': 'GeneralValue', 'target-user': 'User', 'uri': 'GeneralValue',
                          'url': 'GeneralValue', 'user-agent': 'GeneralValue', 'vulnerability': 'GeneralValue',
                          'windows-scheduled-task': 'GeneralValue', 'windows-service-name': 'GeneralValue',
                          'windows-service-displayname': 'GeneralValue'}

misp_attr_to_item_type = {'authentihash': 'StringValue', 'cdhash': 'StringValue', 'domain': 'StringValue',
                          'email-dst': 'StringValue', 'email-reply-to': 'StringValue', 'email-src': 'StringValue',
                          'email-subject': 'StringValue', 'filename': 'StringValue', 'impfuzzy': 'StringValue',
                          'imphash': 'StringValue', 'md5': 'StringValue', 'pehash': 'StringValue', 'sha1': 'StringValue',
                          'sha224': 'StringValue', 'sha256': 'StringValue', 'sha384': 'StringValue',
                          'sha512': 'StringValue', 'sha512/224': 'StringValue', 'sha512/256': 'StringValue',
                          'ssdeep': 'StringValue', 'tlsh': 'StringValue', 'hassh-md5': 'StringValue',
                          'hasshserver-md5': 'StringValue', 'ja3-fingerprint-md5': 'StringValue',
                          'hostname': 'StringValue', 'ip-dst': 'IP', 'ip-src': 'IP', 'link': 'StringValue',
                          'mime-type': 'StringValue', 'mutex': 'StringValue', 'named pipe': 'StringValue',
                          'regkey': 'StringValue', 'target-email': 'StringValue', 'target-machine': 'StringValue',
                          'target-user': 'StringValue', 'uri': 'StringValue', 'url': 'StringValue',
                          'user-agent': 'StringValue', 'vulnerability': 'StringValue',
                          'windows-scheduled-task': 'StringValue', 'windows-service-name': 'StringValue',
                          'windows-service-displayname': 'StringValue'}

misp_attr_to_data_type = {'authentihash': 'String', 'cdhash': 'String', 'domain': 'String', 'email-dst': 'String',
                          'email-reply-to': 'String', 'email-src': 'String', 'email-subject': 'String',
                          'filename': 'String', 'impfuzzy': 'String', 'imphash': 'String', 'md5': 'String',
                          'pehash': 'String', 'sha1': 'String', 'sha224': 'String', 'sha256': 'String',
                          'sha384': 'String', 'sha512': 'String', 'sha512/224': 'String', 'sha512/256': 'String',
                          'ssdeep': 'String', 'tlsh': 'String', 'hassh-md5': 'String', 'hasshserver-md5': 'String',
                          'ja3-fingerprint-md5': 'String', 'hostname': 'String', 'ip-dst': 'IP', 'ip-src': 'IP',
                          'link': 'String', 'mime-type': 'String', 'mutex': 'String', 'named pipe': 'String',
                          'regkey': 'String', 'target-email': 'String', 'target-machine': 'String',
                          'target-user': 'String', 'uri': 'String', 'url': 'String', 'user-agent': 'String',
                          'vulnerability': 'String', 'windows-scheduled-task': 'String',
                          'windows-service-name': 'String', 'windows-service-displayname': 'String'}


def save_intel_to_file(misp_object, _file_name):
    list_file = open(_file_name, 'w', encoding='utf-8')
    for value in misp_object:
        print(str(value.encode('utf-8'), 'utf-8'), file=list_file)
    list_file.close()


def save_intel_to_lr_list(misp_object, lr_api_gw, lr_api_key, list_name, basic: bool = True, list_attrs: {} = None):
    list_api = LogRhythmListManagement(lr_api_gw, lr_api_key)
    warn_lists = list_api.get_lists_summary(list_name=list_name)
    context = None
    data_type = None
    item_type = None
    list_type = None
    if warn_lists is None or len(warn_lists) < 1:
        if basic:
            if list_name == 'MISP WarnList: Destination Address' or list_name == 'MISP WarnList: Source Address' or \
                    list_name == 'MISP WarnList: Users':
                context = None
                list_type = lr_list_name_to_list_type[list_name]
            else:
                context = lr_list_name_to_context[list_name]
        else:
            context = list_attrs['context']
            list_type = list_attrs['list_type']

        warn_lists = []
        warn_tmp = list_api.create_list(list_name, list_type=list_type, use_context=context)
        warn_lists.append(warn_tmp)

        if len(warn_lists) > 0:
            guid = warn_lists[0]['guid']
            if basic:
                data_type = lr_list_to_data_type[list_name]
                item_type = lr_list_to_item_type[list_name]
            else:
                data_type = list_attrs['data_type']
                item_type = list_attrs['item_type']
            for item in misp_object:
                try:
                    list_api.insert_item(guid, item, item, list_item_data=data_type, list_item_type=item_type)
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

    def get_list_for_id(self, list_id: int, basic=True):
        list_name = None
        data_type = None
        item_type = None
        context = None
        list_type = None

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
                        context = misp_attr_to_context[attr.strip()]
                        data_type = misp_attr_to_data_type[attr.strip()]
                        item_type = misp_attr_to_item_type[attr.strip()]
                        list_type = misp_attr_to_list_type[attr.strip()]
                        break
                if list_name is not None:
                    if basic:
                        return list_name, None, None, None
                    else:
                        list_name = "MISP WarnList: " + item['Warninglist']['name']
                        return list_name, context, data_type, item_type, list_type

    def get_lists(self, enabled: WarnListFilter = WarnListFilter.Enabled, basic=True):
        warn_lists = self.misp_intel.get_warnlists(enabled)
        list_name = None
        data_type = None
        item_type = None
        context = None
        list_type = None

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
                    context = misp_attr_to_context[attr.strip()]
                    data_type = misp_attr_to_data_type[attr.strip()]
                    item_type = misp_attr_to_item_type[attr.strip()]
                    list_type = misp_attr_to_list_type[attr.strip()]
                    break
            if list_name is None:
                continue
            if not basic:
                list_name = "MISP WarnList: " + item['Warninglist']['name']
                list_value = {'list': list_name, 'id': id, 'context': context, 'data_type': data_type,
                              'item_type': item_type,'list_type': list_type}
            else:
                list_value = {'list': list_name, 'id': id, 'context': None, 'data_type': None, 'item_type': None,
                              'list_type': None}
            return_list.append(list_value)
        return return_list


def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


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
    parser.add_argument('--disabled', type=str2bool, nargs='?', const=True,
                        help='Flag to get disabled Lists as well', default=False)
    parser.add_argument('--original', type=str2bool, nargs='?', const=False,
                        help='Flag to create/use MISP Original Lists names instead of basic ones', default=True)
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
            lists = api.get_lists(enabled=WarnListFilter.All, basic=not args.original)
        else:
            lists = api.get_lists(enabled=WarnListFilter.Enabled, basic=not args.original)
        for _list in lists:
            lists_items = api.process_warn_list(_list['id'])
            if args.mode == 'api':
                save_intel_to_lr_list(lists_items, args.lr_api_gw, args.lr_api_key, _list['list'], basic=False,
                                      list_attrs=_list)
            else:
                file_name = _list['list'].replace(": ", " - ") + '.lst'
                file_path = os.path.join(args.lr_list_directory, file_name)
                save_intel_to_file(lists_items, file_path)
    else:
        lists_items = api.process_warn_list(args.list_id)
        if args.mode == 'api':
            list_name, context, data_type, item_type, list_type = api.get_list_for_id(args.list_id,
                                                                                      basic=not args.original)
            list_attrs = {'context': context, 'data_type': data_type, 'item_type': item_type,'list_type': list_type}
            save_intel_to_lr_list(lists_items, args.lr_api_gw, args.lr_api_key, list_name, basic=not args.original,
                                  list_attrs=list_attrs)
        else:
            list_name, context, data_type, item_type, list_type = api.get_list_for_id(args.list_id)
            file_name = list_name.replace(": ", " - ") + '.lst'
            file_path = os.path.join(args.lr_list_directory, file_name)
