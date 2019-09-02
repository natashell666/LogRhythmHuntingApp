import urllib.parse
import requests
import logging
import json
from datetime import datetime
from datetime import timedelta
import time
from enum import Enum


class EvidenceType(Enum):
    ALARM= 'alarm'
    USER_EVENT = 'userEvents'
    LOG = 'log'
    NOTE = 'note'
    FILE = 'file'


class LogRhythmCaseManagement:
    logrhythm_summary_fields = {
        1: 'Direction', 2: 'Priority', 3: 'Normal Message Date', 4: 'First Normal Message Date',
        5: 'Last Normal Message Date', 6: 'Count', 7: 'MessageDate', 8: 'Entity', 9: 'Log Source',
        10: 'Log Source Host', 11: 'Log Source Type', 12: 'Log Class Type', 13: 'Log Class', 14: 'Common Event',
        15: 'MPE Rule', 16: 'Source', 17: 'Destination', 18: 'Service', 19: 'Known Host', 20: 'Known Host (Origin)',
        21: 'Known Host (Impacted)', 22: 'Known Service', 23: 'IP', 24: 'IP Address (Origin)',
        25: 'IP Address (Impacted)', 26: 'Host Name', 27: 'Host Name (Origin)', 28: 'Host Name (Impacted)',
        29: 'Port (Origin)', 30: 'Port (Impacted)', 31: 'Protocol', 32: 'User (Origin)', 33: 'User (Impacted)',
        34: 'Sender', 35: 'Recipient', 36: 'Subject', 37: 'Object', 38: 'Vendor Message ID', 39: 'Vendor Message Name',
        40: 'Bytes In', 41: 'Bytes Out', 42: 'Items In', 43: 'Items Out', 44: 'Duration', 45: 'Time Start',
        46: 'Time End', 47: 'Process', 48: 'Amount', 49: 'Quantity', 50: 'Rate', 51: 'Size', 52: 'Domain (Impacted)',
        53: 'Group', 54: 'URL', 55: 'Session', 56: 'Sequence', 57: 'Network (Origin)', 58: 'Network (Impacted)',
        59: 'Location (Origin)', 60: 'Country (Origin)', 61: 'Region (Origin)', 62: 'City (Origin)',
        63: 'Location (Impacted)', 64: 'Country (Impacted)', 65: 'Region (Impacted)', 66: 'City (Impacted)',
        67: 'Entity (Origin)', 68: 'Entity (Impacted)', 69: 'Zone (Origin)', 70: 'Zone (Impacted)', 72: 'Zone',
        73: 'User', 74: 'Address', 75: 'MAC', 76: 'NATIP', 77: 'Interface', 78: 'NATPort',
        79: 'Entity (Impacted or Origin)', 80: 'RootEntity', 100: 'Message', 200: 'MediatorMsgID', 201: 'MARCMsgID',
        1040: 'MAC (Origin)', 1041: 'MAC (Impacted)', 1042: 'NATIP (Origin)', 1043: 'NATIP (Impacted)',
        1044: 'Interface (Origin)', 1045: 'Interface (Impacted)', 1046: 'PID', 1047: 'Severity', 1048: 'Version',
        1049: 'Command', 1050: 'ObjectName', 1051: 'NATPort (Origin)', 1052: 'NATPort (Impacted)',
        1053: 'Domain (Origin)', 1054: 'Hash', 1055: 'Policy', 1056: 'Vendor Info', 1057: 'Result', 1058: 'Object Type',
        1059: 'CVE', 1060: 'UserAgent', 1061: 'Parent Process Id', 1062: 'Parent Process Name',
        1063: 'Parent Process Path', 1064: 'Serial Number', 1065: 'Reason', 1066: 'Status', 1067: 'Threat Id',
        1068: 'Threat Name', 1069: 'Session Type', 1070: 'Action', 1071: 'Response Code',
        1072: 'User (Origin) Identity ID', 1073: 'User (Impacted) Identity ID', 1074: 'Sender Identity ID',
        1075: 'Recipient Identity ID', 1076: 'User (Origin) Identity', 1077: 'User (Impacted) Identity',
        1078: 'Sender Identity', 1079: 'Recipient Identity', 1080: 'User (Origin) Identity Domain',
        1081: 'User (Impacted) Identity Domain', 1082: 'Sender Identity Domain', 1083: 'Recipient Identity Domain',
        1084: 'User (Origin) Identity Company', 1085: 'User (Impacted) Identity Company',
        1086: 'Sender Identity Company', 1087: 'Recipient Identity Company', 1088: 'User (Origin) Identity Department',
        1089: 'User (Impacted) Identity Department', 1090: 'Sender Identity Department',
        1091: 'Recipient Identity Department', 1092: 'User (Origin) Identity Title',
        1093: 'User (Impacted) Identity Title', 1094: 'Sender Identity Title', 1095: 'Recipient Identity Title',
        10001: 'Source Or Destination', 10002: 'Port (Origin or Impacted)', 10003: 'Network (Origin or Impacted)',
        10004: 'Location (Origin or Impacted)', 10005: 'Country (Origin or Impacted)',
        10006: 'Region (Origin or Impacted)', 10007: 'City (Origin or Impacted)', 10008: 'Bytes In/Out',
        10009: 'Items In/Out'
    }

    def __init__(self, logrhythm_url, api_key, debug=False):
        self.logrhythm_url = logrhythm_url
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

    @staticmethod
    def create__evidence_note(case_search_tag, action, *args):
        evidence_note = '[' + case_search_tag + '] ' + action + ' Case'
        if len(args) > 0:
            evidence_note = evidence_note + ' (Fields '
            fields_note = ','.join(map(str, args))
            evidence_note = evidence_note + fields_note + ' )'
        return evidence_note

    def get_case_by_id(self, case_id):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases/' + case_id
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)
        logrhythm_response = requests.get(logrhythm_case_url, headers=logrhythm_headers, verify=False)
        if logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))
        return logrhythm_response.json()

    def get_case_earliest_evidence(self, case_id):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases/' + case_id + '/metrics'
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)
        logrhythm_response = requests.get(logrhythm_case_url, headers=logrhythm_headers, verify=False)
        if logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))
        return logrhythm_response.json()

    def create_srpc_tag(self, search_tag):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, '/lr-case-api/tags')
        logrhythm_request = {'text': search_tag}
        logrhythm_response = requests.post(logrhythm_case_url, json=logrhythm_request, headers=logrhythm_headers,
                                           verify=False)
        print(str(logrhythm_response.json()))
        return logrhythm_response.json()

    def find_srpc_tag(self, search_tag):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/tags?tag=' + search_tag
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)
        logrhythm_response = requests.get(logrhythm_case_url, headers=logrhythm_headers, verify=False)
        tag_response = logrhythm_response.json()
        print(str(tag_response))
        for tag in tag_response:
            if 'text' in tag and tag['text'] == search_tag:
                return tag['number']
        return -1

    def get_all_cases(self, case_status: list, delta_seconds, initial_date=None, count=1000, direction='desc', page=0,
                      order_by='dateUpdated'):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases?statusNumber=' + ','.join(str(x) for x in case_status)
        if initial_date is None:
            updated_after = datetime.now() + timedelta(seconds=-abs(delta_seconds))
        else:
            updated_after = initial_date + timedelta(seconds=-abs(delta_seconds))
        logrhythm_headers.update({'updatedAfter': updated_after.strftime('%Y-%m-%dT%H:%M:%S.%fZ')})

        logrhythm_headers.update({'orderBy': order_by})
        logrhythm_headers.update({'direction': direction})
        if count < 2:
            count = 100
        logrhythm_headers.update({'count': str(count)})
        logrhythm_headers.update({'offset': str(page * count)})

        print(str(logrhythm_headers))

        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)

        print(str(logrhythm_case_url))

        logrhythm_response = requests.get(logrhythm_case_url, headers=logrhythm_headers, verify=False)

        print(str(logrhythm_response))

        if logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))

        return logrhythm_response.json()

    def find_srpc_case(self, alarm_rule_name, case_search_status, case_search_tag, case_search_days,
                       case_search_tag_id=-1, page=0, *args):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases?statusNumber=' + case_search_status
        filter_by_evidence = False
        evidence_note = ''
        if len(args) > 0:
            filter_by_evidence = True
            evidence_note = self.create__evidence_note(case_search_tag, 'Created', args)
            if case_search_tag_id != -1:
                logrhythm_case_uri = logrhythm_case_uri + '&tagNumber=' + case_search_tag_id

# Calculate the filter on how far back to search
        if case_search_days is not None:
            if case_search_days > 0:
                updated_after = datetime.now() + timedelta(days=-case_search_days)
                logrhythm_headers.update({'updatedAfter': updated_after.strftime('%Y-%m-%dT%H:%M:%S%z')})

# Sort the cases to get the most recent
        count = 2
        logrhythm_headers.update({'orderBy': 'dateUpdated'})
        logrhythm_headers.update({'direction': 'desc'})
        logrhythm_headers.update({'count': count})
        logrhythm_headers.update({'offset': page * count})

        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)
        logrhythm_response = requests.get(logrhythm_case_url, headers=logrhythm_headers, verify=False)
        if logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))

        found_case = False

        response_json = logrhythm_response.json()
        case_ids = response_json['id']
        for case_id in case_ids:
            case_evidence_uri = '/lr-case-api/cases/' + case_id + '/evidence'
            case_evidence_url = urllib.parse.urljoin(self.logrhythm_url, case_evidence_uri)
            case_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
            case_response = requests.get(case_evidence_url, logrhythm_headers=case_headers, verify=False)
            if logrhythm_response.status_code != 200:
                raise Exception('LogRhythm Case API didn\'t response correctly for Evidence: {}'.
                                format(logrhythm_response.status_code))
            if case_response is not None:
                case_json = case_response.json()
                case_alarms = case_json['alarm']
                if case_alarms is not None and alarm_rule_name in case_alarms['AlarmRuleName']:
                    case_notes = case_json['text']
                    if not filter_by_evidence:
                        found_case = True
                        break
                    else:
                        if case_notes is not None and evidence_note in case_notes:
                            found_case = True
                            break

        if not found_case:
            if len(case_ids) > count and page < 10:
                page = page + 1
                srpc_case_response = self.find_srpc_case(alarm_rule_name, case_search_status, case_search_tag,
                                                         case_search_tag_id, page, *args)
                return srpc_case_response
        else:
            return response_json

    def add_srpc_collaborator(self, collaborator_id, case_id):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases/' + case_id + '/actions/addCollaborators'
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)
        logrhythm_request = {'numbers': [collaborator_id]}
        logrhythm_response = requests.put(logrhythm_case_url, json=logrhythm_request, headers=logrhythm_headers,
                                          verify=False)
        if logrhythm_response.status_code != 200:
            return False
        return True

    def change_srpc_owner(self, owner_id, case_id):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases/' + case_id + '/actions/changeOwner'
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)
        logrhythm_request = {'number': owner_id}
        logrhythm_response = requests.put(logrhythm_case_url, json=logrhythm_request, headers=logrhythm_headers,
                                          verify=False)
        if logrhythm_response.status_code != 200:
            return False
        return True

    def change_srpc_status(self, status_id, case_id):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases/' + case_id + '/actions/changeStatus'
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)
        logrhythm_request = {'statusNumber': status_id}
        logrhythm_response = requests.put(logrhythm_case_url, json=logrhythm_request, headers=logrhythm_headers,
                                          verify=False)
        if logrhythm_response.status_code != 200:
            return False
        return True

    def add_srpc_evidence_alarm(self, alarm_id, case_id):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases/' + case_id + '/evidence/alarms'
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)
        logrhythm_request = {'alarmNumbers': [alarm_id]}
        logrhythm_response = requests.put(logrhythm_case_url, json=logrhythm_request, headers=logrhythm_headers,
                                          verify=False)
        if logrhythm_response.status_code != 200:
            return False
        return True

    def add_srpc_evidence_note(self, note, case_id):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases/' + case_id + '/evidence/note'
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)

# Validar si no se debe reemplazar " en note

        logrhythm_request = {'text': note}
        logrhythm_response = requests.post(logrhythm_case_url, json=logrhythm_request, headers=logrhythm_headers,
                                           verify=False)
        if logrhythm_response.status_code != 201:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))
        return logrhythm_response.json()

    def add_srpc_tag(self, tag_id, case_id):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases/' + case_id + '/actions/addTags'
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)
        logrhythm_request = {'numbers': [tag_id]}
        logrhythm_response = requests.put(logrhythm_case_url, json=logrhythm_request, headers=logrhythm_headers,
                                          verify=False)
        if logrhythm_response.status_code != 200:
            return False
        return True

# TODO: Request the caseName as an option in the function so we can add the Event MISP Name

    def create_srpc_case(self, case_search_tag, owner_id, priority, alarm_rule_name, alarm_id, case_search_tag_id=-1,
                         *args):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        case_name = alarm_rule_name
        if len(args) > 0:
            case_name = case_name + ' (Fields '
            case_fields = ','.join(map(str, args))
            case_name = case_name + case_fields + ' )'

        if priority < 0 or priority > 5:
            # TODO: Add Loggers
            priority = 3

        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, '/lr-case-api/cases')
        logrhythm_request = {'name': case_name, 'priority': priority, 'summary': 'Created by the Automation Plugin'}
        logrhythm_response = requests.post(logrhythm_case_url, json=logrhythm_request, headers=logrhythm_headers,
                                           verify=False)
        if logrhythm_response.status_code != 201:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))
        if logrhythm_response is None or logrhythm_response.json()['id'] is None:
            raise Exception('LogRhythm Case API didn\'t create the case correctly: {}'.
                            format(logrhythm_response.status_code))

        logrhythm_case = logrhythm_response.json()
# Adding the Owner as Collaborator
        if owner_id != 0 and logrhythm_case['owner'] != owner_id:
            self.add_srpc_collaborator(owner_id, logrhythm_case['id'])
            self.change_srpc_owner(owner_id, logrhythm_case['id'])

# Adding the Evidence as Notes and Alarms
        self.add_srpc_evidence_alarm(alarm_id, logrhythm_case['id'])
        case_note = self.create__evidence_note(case_search_tag, 'Created', *args)
        self.add_srpc_evidence_note(case_note, logrhythm_case['id'])

        if case_search_tag_id != -1:
            self.add_srpc_tag(case_search_tag_id, logrhythm_case['id'])

        return logrhythm_case['id']

    def create_generic_case(self, case_name, summary, priority=5, external_id=None):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        if priority < 0 or priority > 5:
            priority = 3
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, '/lr-case-api/cases')
        if external_id is not None:
            logrhythm_request = {'name': case_name, 'priority': priority, 'summary': summary, 'externalId': external_id}
        else:
            logrhythm_request = {'name': case_name, 'priority': priority, 'summary': summary}
        logrhythm_response = requests.post(logrhythm_case_url, json=logrhythm_request, headers=logrhythm_headers,
                                           verify=False)
        if logrhythm_response.status_code != 201:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))
        if logrhythm_response is None or logrhythm_response.json()['id'] is None:
            raise Exception('LogRhythm Case API didn\'t create the case correctly: {}'.
                            format(logrhythm_response.status_code))

        logrhythm_case = logrhythm_response.json()
        return logrhythm_case

    def add_srpc_playbook(self, playbook_id, case_id):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases/' + case_id + '/playbooks'
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)
        logrhythm_request = {'id': playbook_id}

# First we look for the Playbook
        logrhythm_response = requests.get(logrhythm_case_url, headers=logrhythm_headers, verify=False)
        if logrhythm_response is not None:
            logrhythm_playbooks = logrhythm_response.json()
            for playbook in logrhythm_playbooks:
                if playbook['originalPlaybookId'] == playbook_id:
                    return None

        logrhythm_response = requests.post(logrhythm_case_url, json=logrhythm_request, headers=logrhythm_headers,
                                           verify=False)
        if logrhythm_response.status_code != 200:
            return None

        if logrhythm_response is not None:
            return logrhythm_response.json()['name']
        else:
            return None

    # Considering using on DDSumaries
    def get_alarm_drill_down(self, alarm_id, retry_count=0, max_retries=5, retry_interval=60):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_drilldown_uri = '/lr-drilldown-cache-api/drilldown/' + alarm_id
        logrhythm_drilldown_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_drilldown_uri)
        logrhythm_response = requests.get(logrhythm_drilldown_url, headers=logrhythm_headers, verify=False)
        if logrhythm_response.status_code != 202:
            # TODO: Add the retry section
            return False
        if (logrhythm_response is None or logrhythm_response.json()['Data'] is None) and retry_count < max_retries:
            retry_count = retry_count + 1
            time.sleep(retry_interval)
            return self.get_alarm_drill_down(alarm_id, retry_count, max_retries, retry_interval)
        return logrhythm_response.json()['Data']

    def get_evidence_for_case(self, case_id, date_updated, evidence_type: list() = None):
        logrhythm_headers = {'Content-Type': 'application/json', "Authorization": "Bearer " + self.api_key}
        logrhythm_case_uri = '/lr-case-api/cases/' + case_id + '/evidence'

        if evidence_type is not None:
            list_evidence = ','.join(x.value for x in evidence_type)
            logrhythm_case_uri = logrhythm_case_uri + '?type=' + list_evidence
        logrhythm_case_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_case_uri)
        print(logrhythm_case_url)

        logrhythm_response = requests.get(logrhythm_case_url, headers=logrhythm_headers, verify=False)

        print(str(logrhythm_response))

        if logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))

        return logrhythm_response.json()

if __name__ == '__main__':
    lr_case = LogRhythmCaseManagement('https://lr.apigw.me:8501', 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQi')

    #response = lr_case.create_generic_case('Python API Case2', 'Sumarizado del Caso', priority=1,
    #                                       external_id='1441 - Ephemeral indicators of SPAM INCIDENTS collected '
    #                                                   'from block or filter lists')
    #lr_case.add_srpc_evidence_note('Test de \nNota Python3', '6050553A-7884-4B1F-A6D3-5FD5B5C198A6')
    #print(str(lr_case.find_srpc_tag('misp')))
    #print(str(lr_case.create_srpc_tag('natas1_tag2')))
    #print(str(lr_case.add_srpc_tag(12,'28EACB66-9B89-49E5-A7DA-236F7BC75357')))

    #print(str(lr_case.add_srpc_collaborator(1, '28EACB66-9B89-49E5-A7DA-236F7BC75357')))

    #print(str(lr_case.change_srpc_owner(1, '28EACB66-9B89-49E5-A7DA-236F7BC75357')))
    #BC3B367A-28CB-4E65-BE74-3B4ED5077976
    #print(str(lr_case.add_srpc_playbook('BC3B367A-28CB-4E65-BE74-3B4ED5077976', '28EACB66-9B89-49E5-A7DA-236F7BC75357')))

    # 2 --> Completed
    # 1 --> created
    # 3 --> Incident
    # 4 --> Mitigated
    # 5 --> Resolved
    # print(str(lr_case.change_srpc_status(5, '28EACB66-9B89-49E5-A7DA-236F7BC75357')))

    #case_tags = ['misp', 'incident', 'collaboration', 'sharing', 'lr_integration']
    #for tag in case_tags:
    #    print('Adding tag: ' + tag)
    #    tag_id = lr_case.find_srpc_tag(tag)
    #    print('Adding tag: ' + tag + ' with tag_id: ' + str(tag_id))
    #    if tag_id == -1:
    #        print('Tag not found, another created: ' + str(tag_id))
        #    tag_response = lr_case.create_srpc_tag('natas_tag1')
        #    tag_id = tag_response['number']
        #lr_case.add_srpc_tag(tag_id, case_uuid)

    #print(','.join(str(x) for x in [1, 2]))
    #response = lr_case.get_all_cases([1, 3], 3600)
    #response = lr_case.get_evidence_for_case('EA285646-52D0-4AAC-A004-E8E90AD3E3E4', None, [EvidenceType.ALARM])
    #response = lr_case.get_evidence_for_case('EA285646-52D0-4AAC-A004-E8E90AD3E3E4', None)
    #print(str(response))
    #print('---------------')
    response = lr_case.get_alarm_drill_down('9604')
    print(response)

    if 'RuleBlocks' in response['DrillDownResults']:
        for rule_block in response['DrillDownResults']['RuleBlocks']:
            if 'DDSummaries' in rule_block:
                for summary in rule_block['DDSummaries']:
                    #print(summary['PIFType'])
                    logs = json.loads(summary['DrillDownSummaryLogs'])
                    #print(logs)
                    if len(logs) > 0:
                        print(str(lr_case.logrhythm_summary_fields[summary['PIFType']]) + ' -- ' + logs[0]['field'])
