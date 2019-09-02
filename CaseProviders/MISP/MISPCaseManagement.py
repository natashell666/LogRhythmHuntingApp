import yaml
import re
import json
from pymisp import MISPEvent, ExpandedPyMISP
from enum import Enum


class MISPDistribution(Enum):
    ORGANIZATION = 0
    COMMUNITY = 1
    COMMUNITIES = 2
    ALL = 3
    INHERIT = 4


class MISPThreatLevel(Enum):
    HIGH = 1
    MEDIUM = 2
    LOW = 3
    UNDEFINED = 3


class MISPAnalysis(Enum):
    INITIAL = 0
    ONGOING = 1
    COMPLETED = 2


class StringOperator(Enum):
    EQ = 'Eq'
    CONTAINS = 'Contains'
    REGEX = 'Regex'


class MISPDataType(Enum):
    DST_IP = 0
    SRC_IP = 1
    COMMENT = 2
    TEXT = 3
    SUBJECT = 4
    MUTEX = 5
    FILENAME = 6
    HOSTNAME = 7
    DOMAIN = 8
    DOMAIN_IP = 9
    EMAIL_SRC = 10
    EMAIL_DST = 11
    HASH = 12
    OBJECT = 13
    REG_KEY = 14
    URL = 15
    LOGIN = 16
    USER_AGENT =17
    ACCOUNT = 18


class MISPCaseManagement:
    def __init__(self, config_file='C:\\automation-hunting\\misp\\conf\\misp-case-provider.yaml', debug=False):
        self.misp_url = None
        self.api_key = None
        self.verify_cert = False

        if not self.get_config_data(config_file):
            raise Exception('Invalid Configuration File')

        self.misp_api = ExpandedPyMISP(self.misp_url, self.api_key, self.verify_cert, debug=debug)

        self.add_ioc_functions = [self.misp_api.add_ipdst, self.misp_api.add_ipsrc, self.misp_api.add_internal_comment,
                                  self.misp_api.add_internal_text, self.misp_api.add_email_subject,
                                  self.misp_api.add_mutex, self.misp_api.add_filename, self.misp_api.add_hostname,
                                  self.misp_api.add_domain, self.misp_api.add_domain_ip, self.misp_api.add_email_src,
                                  self.misp_api.add_email_dst, self.misp_api.add_hashes, self.misp_api.add_object,
                                  self.misp_api.add_regkey, self.misp_api.add_url, self.misp_api.add_user,
                                  self.misp_api.add_useragent, self.misp_api.add_target_user]

    def get_config_data(self, yaml_file):
        with open(yaml_file, 'r') as ymlfile:
            cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

        valid = False
        if self.validate_cfg_yml(cfg):
            self.misp_url = cfg['misp']['misp_url']
            self.api_key = cfg['misp']['api_key']
            self.verify_cert = cfg['misp']['verify_cert']
            valid = True
        return valid

    @staticmethod
    def validate_cfg_yml(cfg):
        if 'misp' not in cfg:
            print('Not main')
            return False
        else:
            if 'misp_url' not in cfg['misp'] or 'api_key' not in cfg['misp']:
                return False
        return True

    def create_full_event(self, info, distribution: MISPDistribution = MISPDistribution.ORGANIZATION,
                          threat_level: MISPThreatLevel = MISPThreatLevel.MEDIUM,
                          analysis: MISPAnalysis = MISPAnalysis.INITIAL, attributes: list = None, tags: list = None):
        new_event = MISPEvent()
        new_event.distribution = distribution.value
        new_event.threat_level_id = threat_level.value
        new_event.analysis = analysis.value
        new_event.info = info
        if attributes is not None:
            new_event.Attribute = list()
        if tags is not None:
            new_event.Tag = list()

        event = self.misp_api.add_event(new_event)

        self.misp_api.get_all_tags()

        print(event.to_json())
        return event

    def search_tag(self, tag_value, operator: StringOperator = StringOperator.EQ, sensitive=True, **kwargs):
        tags = self.misp_api.get_tags_list()
        ret_tags = list()
        for tag in tags:
            found = False
            if operator == StringOperator.EQ:
                if sensitive:
                    if tag['name'] == tag_value:
                        found = True
                else:
                    if tag['name'].lower() == tag_value.lower():
                        found = True
            elif operator == StringOperator.CONTAINS:
                if sensitive:
                    if tag_value in tag['name']:
                        found = True
                else:
                    if tag['name'].lower() == tag_value.lower():
                        found = True
            elif operator == StringOperator.REGEX:
                if sensitive:
                    if re.search(tag_value, tag['name']) is not None:
                        found = True
                else:
                    if re.search(tag_value.lower(), tag['name'].lower()) is not None:
                        found = True
            else:
                print('Unsupported')
            if found and len(kwargs) > 0:
                if 'exportable' in kwargs:
                    if tag['exportable'] == kwargs['exportable']:
                        found = True
                    else:
                        found = False
                if 'org_id' in kwargs:
                    if tag['org_id'] == str(kwargs['org_id']):
                        found = True
                    else:
                        found = False
                if 'user_id' in kwargs:
                    if tag['user_id'] == str(kwargs['user_id']):
                        found = True
                    else:
                        found = False
                if 'hide_tag' in kwargs:
                    if tag['hide_tag'] == kwargs['hide_tag']:
                        found = True
                    else:
                        found = False
            if found:
                ret_tags.append(tag)
        return ret_tags

    def create_tag(self, tag_data):
        new_tag = self.misp_api.new_tag(name=tag_data['name'], colour=tag_data['colour'],
                                        exportable=tag_data['exportable'], hide_tag=tag_data['hide_tag'])
        return new_tag

    def search_event(self, **kwargs):
        result = None
        if 'event_name' in kwargs:
            result = self.misp_api.search(eventinfo=kwargs['event_name'])
        elif 'event_id' in kwargs:
            result = self.misp_api.search(eventid=kwargs['event_id'])
        elif 'uuid' in kwargs:
            result = self.misp_api.search(uuid=kwargs['uuid'])
        else:
            print('Unsupported search filter')

        return result

    def add_ioc(self, event, data_type:MISPDataType, **kwargs):
        if data_type.value == 12:
            if 'domain' in kwargs and 'ip' in kwargs:
                self.add_ioc_functions[data_type.value](event, kwargs['domain'], kwargs['ip'])
            else:
                print('Missing parameters for: ' + data_type.name)
        elif data_type.value == 9:
            if 'md5' in kwargs:
                self.add_ioc_functions[data_type.value](event, md5=kwargs['md5'])
            if 'sha1' in kwargs:
                self.add_ioc_functions[data_type.value](event, sha1=kwargs['sha1'])
            if 'sha256' in kwargs:
                self.add_ioc_functions[data_type.value](event, sha256=kwargs['sha256'])
            if 'ssdeep' in kwargs:
                self.add_ioc_functions[data_type.value](event, ssdeep=kwargs['ssdeep'])
        else:
            if 'value' in kwargs:
                print('ADDING ATTRIBUTE')
                self.add_ioc_functions[data_type.value](event, kwargs['value'])
            else:
                print('Missing parameters for: ' + data_type.name)


if __name__ == '__main__':
    api = MISPCaseManagement()
    event = api.search_event(event_id=1483)
    if event is not None and len(event) > 0:
        api.add_ioc(event[0], MISPDataType.DOMAIN, value='natashell.me.mx')
    else:
        print('Error searching the event')
    # data = api.search_tag('malware: Zebrocy', operator=StringOperator.EQ, sensitive=False, exportable=True, user_id=0)
    # print(str(len(data)) + ' --> ')
    # print(json.dumps(data, indent=2))
