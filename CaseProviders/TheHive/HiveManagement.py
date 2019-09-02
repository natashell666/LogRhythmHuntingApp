from __future__ import print_function
from __future__ import unicode_literals

import requests
import json
import uuid
import yaml
import urllib.parse
from enum import Enum

from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, Case, CaseTask, CustomFieldHelper, CaseObservable
from thehive4py.query import *


class TLP(Enum):
    WHITE = 0
    GREEN = 1
    AMBER = 2
    RED = 3


class HiveSeverity(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class PAP(Enum):
    WHITE = 0
    GREEN = 1
    AMBER = 2
    RED = 3


class HiveDataType(Enum):
    IP = 'ip'
    DOMAIN = 'domain'
    URL = 'url'
    MAIL = 'mail'
    FQDN = 'fqdn'
    OTHER = 'other'
    FILE = 'file'
    URI = 'uri_path'
    UA = 'user-agent'
    HASH = 'hash'
    EMAIL = 'email'
    SUBJECT = 'mail_subject'
    REGISTRY = 'registry'
    REGEXP = 'regexp'
    FILENAME = 'filename'


class HiveManagement:
    def __init__(self, config_file='C:\\automation-hunting\\the-hive\\conf\\thehive-provider.yaml'):

        self.hive_url = None
        self.api_key = None
        self.alert_tags = None
        self.source = None
        self.alert_type = None
        self.case_tags = None
        self.ioc_tags = None

        if not self.get_config_data(config_file):
            raise Exception('Invalid Configuration File')

        self.api = TheHiveApi(self.hive_url, self.api_key)

    def get_config_data(self, yaml_file):
        with open(yaml_file, 'r') as ymlfile:
            cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

        valid = False
        if self.validate_cfg_yml(cfg):
            self.hive_url = cfg['hive']['hive_url']
            self.api_key = cfg['hive']['api_key']
            self.alert_tags = cfg['hive']['alert_tags']
            self.source = cfg['hive']['source']
            self.alert_type = cfg['hive']['alert_type']
            self.case_tags = cfg['hive']['case_tags']
            self.ioc_tags = cfg['hive']['ioc_tags']
            valid = True
        return valid

    @staticmethod
    def validate_cfg_yml(cfg):
        if 'hive' not in cfg:
            print('Not main')
            return False
        else:
            if 'hive_url' not in cfg['hive'] or 'api_key' not in cfg['hive']:
                return False
        return True

    def create_alarm(self, title, source_ref=None, description='N/A', alert_type='external', source='LogRhythm',
                     iocs=None, additional_fields=None, additional_tags=None, tlp=TLP.AMBER, pap=PAP.AMBER,
                     severity=HiveSeverity.MEDIUM):

        if source_ref is None:
            source_ref = str(uuid.uuid4())[0:6]

        alert_tags = self.alert_tags.copy()
        if additional_tags is not None:
            for additional_tag in additional_tags:
                alert_tags.append(additional_tag)

        custom_fields_helper = CustomFieldHelper()
        if additional_fields is not None:
            for field in additional_fields:
                custom_fields_helper.add_string(field['name'], field['value'])
        custom_fields = custom_fields_helper.build()

        artifacts = list()
        if iocs is not None:
            for ioc in iocs:
                artifacts.append(AlertArtifact(dataType=ioc['type'].value, data=ioc['value']))

        hive_alert = Alert(title=title, tlp=tlp.value, tags=alert_tags, description=description, type=alert_type,
                           source=source, sourceRef=source_ref, pap=pap.value, artifacts=artifacts,
                           customFields=custom_fields, severity=severity.value)

        response = self.api.create_alert(hive_alert)
        if response.status_code == 201:
            print('Alerta Creada Exitosamente')
            print(json.dumps(response.json(), indent=4, sort_keys=True))
        else:
            print('Error')
            print(response.text)

        return response.json()

    def create_case(self, title, tasks=None, tlp=TLP.AMBER, pap=PAP.AMBER, severity=HiveSeverity.MEDIUM,
                    additional_fields=None, additional_tags=None, flag=False, description='N/A'):

        case_tags = self.case_tags.copy()
        if additional_tags is not None:
            for additional_tag in additional_tags:
                case_tags.append(additional_tag)

        custom_fields_helper = CustomFieldHelper()
        if additional_fields is not None:
            for field in additional_fields:
                custom_fields_helper.add_string(field['name'], field['value'])
        custom_fields = custom_fields_helper.build()

        new_tasks = list()
        if tasks is not None:
            for task in tasks:
                new_tasks.append(CaseTask(title=task))

        hive_case = Case(title=title, tlp=tlp.value, pap=pap.value, description=description, tags=case_tags,
                         severity=severity.value, flag=flag, customFields=custom_fields, tasks=new_tasks)

        response = self.api.create_case(hive_case)
        if response.status_code == 201:
            print('Caso Creada Exitosamente')
            print(json.dumps(response.json(), indent=4, sort_keys=True))
        else:
            print('Error')
            print(response.text)

        return response.json()

    def create_case_observable(self, data_type: HiveDataType, value: list, tlp=TLP.AMBER, ioc=True, additional_tags=None,
                               description='LogRhythm IoC'):

        ioc_tags = self.ioc_tags.copy()
        if additional_tags is not None:
            for additional_tag in additional_tags:
                ioc_tags.append(additional_tag)

        hive_observable = CaseObservable(data_type=data_type.value, data=value, tlp=tlp.value, ioc=ioc, tags=ioc_tags,
                                         message=description)

        return hive_observable

    def add_observable_to_case(self, case_id, observable: CaseObservable):
        response = self.api.create_case_observable(case_id, observable)
        if response.status_code == 201:
            print('Observable successfully added to the case')
            print(json.dumps(response.json(), indent=4, sort_keys=True))
        else:
            print('Error')
            print(response.text)

    def search_case(self, title=None, tlp: TLP = None, pap: PAP = None, severity: HiveSeverity = None,
                    or_operator=False):
        if title is None and tlp is None and pap is None and severity is None:
            print('Can\'t search without a filter')
            return None

        operators = list()
        if title is not None:
            operators.append(String('title: ' + urllib.parse.quote(title)))
        if tlp is not None:
            operators.append(Gte('tlp', tlp.value))
        if pap is not None:
            operators.append(Gte('pap', pap.value))
        if severity is not None:
            operators.append(Gte('severity', severity.value))

        if len(operators) == 1:
            query = operators[0]
        else:
            if or_operator:
                query = Or(operators)
            else:
                query = And(operators)

        response = self.api.find_cases(query=query, range='all', sort=[])
        if response.status_code == 200:
            print('Busqueda correcta')
            print(json.dumps(response.json(), indent=4, sort_keys=True))
        else:
            print('Error')
            print(response.text)

        return response.json()

    def promote_alert(self, alert_id):
        response = self.api.promote_alert_to_case(alert_id)
        if response.status_code == 201:
            print('Correct Promotion')
            print(json.dumps(response.json(), indent=4, sort_keys=True))
        else:
            print('Error')
            print(response.text)

        return response.json()


if __name__ == '__main__':
    hive = HiveManagement()
    #hive.create_alarm('Demo API', iocs=[{'type': HiveDataType.IP, 'value': '8.8.8.8'}],
    #                  additional_fields=[{'name': 'logSourceName', 'value': 'demo2lr'}])
    l_tasks = list()
    l_tasks.append('Nts Step 1')
    l_tasks.append('Nts Step 2')
    l_tasks.append('Nts Step 3')
    l_tasks.append('Nts Step 4')
    l_tasks.append('Nts Step 5')
    #hive.create_case('Demo Case API 2', tasks=l_tasks, additional_fields=[{'name': 'logSourceName', 'value': 'demolr'}])

    hive.search_case(title='Demo Case API 2')
