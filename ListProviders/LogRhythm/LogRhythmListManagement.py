import urllib.parse
import requests
import logging
import json


class LogRhythmListManagement:
    logrhythm_list_types = ['Application', 'Classification', 'CommonEvent', 'Host', 'Location', 'MsgSource',
                            'MsgSourceType', 'MPERule', 'Network', 'User', 'GeneralValue', 'Entity', 'RootEntity',
                            'IP', 'IPRange', 'Identity']
    logrhythm_list_status = ['Retired', 'Active']
    logrhythm_list_context = ['None', 'Address', 'DomainImpacted', 'Group', 'HostName', 'Message', 'Object',
                              'Process', 'Session', 'URL', 'User', 'VendorMsgID', 'UserAgent', 'ParentProcessId',
                              'ParentProcessName', 'ParentProcessPath', 'SerialNumber', 'Reason', 'Status',
                              'ThreatId', 'ThreatName', 'SessionType', 'Action', 'ResponseCode']
    logrhythm_list_access = ['Private', 'PublicAll', 'PublicGlobalAdmin', 'PublicGlobalAnalyst',
                             'PublicRestrictedAnalyst', 'PublicRestrictedAdmin']
    logrhythm_list_item_data_type = ['List', 'Int32', 'String', 'PortRange', 'IP', 'IPRange']
    logrhythm_list_item_type = ['List', 'KnownService', 'Classification', 'CommonEvent', 'KnownHost', 'IP',
                                'IPRange', 'Location', 'MsgSource', 'MsgSourceType', 'MPERule', 'Network',
                                'StringValue', 'Port', 'PortRange', 'Protocol', 'HostName', 'ADGroup', 'Entity',
                                'RootEntity', 'DomainOrigin', 'Hash', 'Policy', 'VendorInfo', 'Result', 'ObjectType',
                                'CVE', 'UserAgent', 'ParentProcessId', 'ParentProcessName', 'ParentProcessPath',
                                'SerialNumber', 'Reason', 'Status', 'ThreatId', 'ThreatName', 'SessionType',
                                'Action', 'ResponseCode', 'Identity']

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

    def get_lists_summary(self, list_name=None, max_items=1000):
        print(list_name)
        if list_name is not None:
            logrhythm_headers = {'Content-Type': 'application/json', 'name': list_name,
                                 'MaxItemsThreshold': str(max_items), 'Authorization': 'Bearer ' + self.api_key}
        else:
            logrhythm_headers = {'MaxItemsThreshold': str(max_items), 'Authorization': 'Bearer ' + self.api_key}
        logrhythm_admin_uri = '/lr-admin-api/lists'
        logrhythm_admin_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_admin_uri)
        print(logrhythm_headers)
        logrhythm_response = requests.get(logrhythm_admin_url, headers=logrhythm_headers, verify=False)
        if logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Admin API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))
        return logrhythm_response.json()

    def get_list_details(self, list_uuid, max_items=1000):
        logrhythm_headers = {"MaxItemsThreshold": str(max_items), "Authorization": "Bearer " + self.api_key}
        logrhythm_admin_uri = '/lr-admin-api/lists/' + list_uuid
        logrhythm_admin_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_admin_uri)
        logrhythm_response = requests.get(logrhythm_admin_url, headers=logrhythm_headers, verify=False)
        if logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))
        return logrhythm_response.json()

    def create_list(self, name, list_type='GeneralValue', restricted_read=False, read_access='PublicAll',
                    write_access='PublicAll', auto_import=False, use_pattern=False, replace_mode=False,
                    need_notify=False, expire=False, status='Active', short_desc=None, long_desc=None,
                    use_context=[], import_file=None, ttl=1200, entity_name='Primary Site', owner_id=0):

        if list_type not in self.logrhythm_list_types:
            raise Exception('Incorrect List Type passed as argument')

        auto_import_json = {'enabled': auto_import}
        if auto_import:
            if import_file is None:
                raise Exception('import_file is None, even when auto_import has been selected')
            auto_import_json['usePatterns'] = use_pattern
            auto_import_json['replaceExisting'] = replace_mode

        create_list_request = {'listType': list_type, 'status': status, 'name': name, 'readAccess': read_access,
                               'writeAccess': write_access, 'restrictedRead': restricted_read,
                               'entityName': entity_name, 'doesExpire': expire, 'needToNotify': need_notify,
                               'owner': owner_id, 'timeToLiveSeconds': ttl}
        if short_desc is not None:
            create_list_request['shortDescription'] = short_desc
        if long_desc is not None:
            create_list_request['longDescription'] = long_desc
        if len(use_context) > 0:
            create_list_request['useContext'] = use_context
        else:
            create_list_request['useContext'] = ['None']

        logrhythm_headers = {"Authorization": "Bearer " + self.api_key}
        logrhythm_admin_uri = '/lr-admin-api/lists'
        logrhythm_admin_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_admin_uri)
        logrhythm_response = requests.post(logrhythm_admin_url, json=create_list_request, headers=logrhythm_headers,
                                           verify=False)
        if logrhythm_response.status_code == 400:
            raise Exception('Invalid TTL time, must be greater that 1200')
        if logrhythm_response.status_code == 409:
            raise Exception('Invalid List Name, already in use')
        if logrhythm_response.status_code != 201 or logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))

        return logrhythm_response.json()

    def update_list(self, guid, name, list_type, read_access, write_access, entity_name, restricted_read=False,
                    auto_import=False, use_pattern=False, replace_mode=False, need_notify=False, expire=False,
                    status='Active', short_desc=None, long_desc=None, use_context=[], import_file=None,
                    ttl=1200, owner_id=0):

        if list_type not in self.logrhythm_list_types:
            raise Exception('Incorrect List Type passed as argument')

        auto_import_json = {'enabled': auto_import}
        if auto_import:
            if import_file is None:
                raise Exception('import_file is None, even when auto_import has been selected')
            auto_import_json['usePatterns'] = use_pattern
            auto_import_json['replaceExisting'] = replace_mode

        update_list_request = {'guid': guid, 'listType': list_type, 'status': status, 'name': name,
                               'readAccess': read_access, 'writeAccess': write_access,
                               'restrictedRead': restricted_read, 'entityName': entity_name, 'doesExpire': expire,
                               'needToNotify': need_notify, 'owner': owner_id, 'timeToLiveSeconds': ttl}
        if short_desc is not None:
            update_list_request['shortDescription'] = short_desc
        if long_desc is not None:
            update_list_request['longDescription'] = long_desc
        if len(use_context) > 0:
            update_list_request['useContext'] = use_context
        else:
            update_list_request['useContext'] = ['None']

        logrhythm_headers = {"Authorization": "Bearer " + self.api_key}
        logrhythm_admin_uri = '/lr-admin-api/lists'
        logrhythm_admin_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_admin_uri)
        logrhythm_response = requests.post(logrhythm_admin_url, json=update_list_request, headers=logrhythm_headers,
                                           verify=False)
        if logrhythm_response.status_code == 400:
            raise Exception('Invalid TTL time, must be greater that 1200')
        if logrhythm_response.status_code == 409:
            raise Exception('Invalid List Name, already in use')
        if logrhythm_response.status_code != 200 or logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))

        return logrhythm_response.json()

    def insert_item(self, guid, display_value, value, expiration_date=None, is_expired=False, is_list_item=True,
                    is_pattern=False, list_item_data='String', list_item_type='StringValue'):
        if list_item_data not in self.logrhythm_list_item_data_type:
            raise Exception('Incorrect List Item Data passed as argument')
        if list_item_type not in self.logrhythm_list_item_type:
            raise Exception('Incorrect List Item Type passed as argument')

        item_request = {'displayValue': display_value, 'isExpired': is_expired, 'isListItem': is_list_item,
                        'isPattern': is_pattern, 'listItemDataType': list_item_data, 'listItemType': list_item_type,
                        'value': value}
        if expiration_date is not None:
            item_request['expirationDate'] = expiration_date

        add_item_request = {'items': [item_request]}
        print(str(add_item_request))

        logrhythm_headers = {"Authorization": "Bearer " + self.api_key}
        logrhythm_admin_uri = '/lr-admin-api/lists/' + guid + '/items'
        logrhythm_admin_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_admin_uri)
        print(logrhythm_admin_url)

        logrhythm_response = requests.post(logrhythm_admin_url, json=add_item_request, headers=logrhythm_headers,
                                           verify=False)
        if logrhythm_response.status_code != 200 or logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))

        return logrhythm_response.json()

    def remove_item(self, guid, display_value, value, expiration_date=None, is_expired=False, is_list_item=True,
                    is_pattern=False, list_item_data='String', list_item_type='StringValue'):
        if list_item_data not in self.logrhythm_list_item_data_type:
            raise Exception('Incorrect List Item Data passed as argument')
        if list_item_type not in self.logrhythm_list_item_type:
            raise Exception('Incorrect List Item Type passed as argument')

        item_request = {'displayValue': display_value, 'isExpired': is_expired, 'isListItem': is_list_item,
                        'isPattern': is_pattern, 'listItemDataType': list_item_data, 'listItemType': list_item_type,
                        'value': value}
        if expiration_date is not None:
            item_request['expirationDate'] = expiration_date

        add_item_request = {'items': [item_request]}

        logrhythm_headers = {"Authorization": "Bearer " + self.api_key}
        logrhythm_admin_uri = '/lr-admin-api/lists/' + guid + 'items'
        logrhythm_admin_url = urllib.parse.urljoin(self.logrhythm_url, logrhythm_admin_uri)

        logrhythm_response = requests.delete(logrhythm_admin_url, json=add_item_request, headers=logrhythm_headers,
                                             verify=False)
        if logrhythm_response.status_code != 200 or logrhythm_response.status_code != 200:
            raise Exception('LogRhythm Case API didn\'t response correctly: {}'.
                            format(logrhythm_response.status_code))

        return logrhythm_response.json()


if __name__ == '__main__':
    lr_list = LogRhythmListManagement('https://lr.apigw.me:8501', 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1aWQi')
    print('Len: ' + str(len(lr_list.get_lists_summary(list_name='MISP: HASHES'))))
    data = lr_list.get_lists_summary(list_name='MISP: HASHES')[0]
    print(str(data['name']) + ' ' + str(data['guid']))

    lr_list.insert_item(data['guid'], '0002a41dd42036e566bfe94baa5f78e2a', '0002a41dd42036e566bfe94baa5f78e2a')
    lr_list.insert_item(data['guid'], '0002a41dd42036e566bfe94baa5f78e2a', '0002a41dd42036e566bfe94baa5f78e2a')
