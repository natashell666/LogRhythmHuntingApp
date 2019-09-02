from pymisp import PyMISP


class MISPThreatIntel:
    misp_output = 'json'
    misp_categories = ['Internal reference', 'Targeting data', 'Antivirus detection', 'Payload delivery',
                       'Artifacts dropped', 'Payload installation', 'Persistence mechanism', 'Network activity',
                       'Payload type', 'Attribution', 'External analysis', 'Financial fraud', 'Support Tool',
                       'Social network', 'Person', 'Other']
    misp_threat_level = {'1': 'High', '2': 'Medium', '3': 'Low', '4': 'Undefined'}
    misp_malware_level = {'1': 'Sophisticated APT malware or 0-day attack',
                          '2': 'APT malware', '3': 'Mass-malware', '4': 'No risk'}
    misp_analysis_level = {'0': 'Initial', '1': 'Ongoing', '2': 'Complete'}

    def __init__(self, misp_url, misp_key, misp_verifycert=False, debug=False):
        self.misp_url = misp_url
        self.misp_key = misp_key
        self.misp_verifycert = misp_verifycert
        self.misp_intel = PyMISP(self.misp_url, self.misp_key, self.misp_verifycert, self.misp_output, debug=debug)

    def simple_attribute_search(self, attr_value, attr_type, timestamp='3000d', category=None):
        result = self.misp_intel.search(controller='attributes', value=attr_value, type=attr_type,
                                        event_timestamp=timestamp, category=category)
        if result is None:
            raise Exception('MISP Threat Intelligence didn\'t response correctly')
        return result['response']

    def unstructured_attribute_search(self, attr_value, timestamp='3000d'):
        result = self.misp_intel.search_index(attribute=attr_value, timestamp=timestamp)
        if result is None:
            raise Exception('MISP Threat Intelligence didn\'t response correctly')
        return result['response']

    def get_event_details(self, event_id):
        result = self.misp_intel.get_event(event_id)
        if result is None:
            raise Exception('MISP Threat Intelligence didn\'t response correctly')
        return result

    def get_event_metadata(self, event_id):
        result = self.misp_intel.search_index(eventid=[event_id])
        if result is None:
            raise Exception('MISP Threat Intelligence didn\'t response correctly')
        return result['response']


if __name__ == '__main__':
    misp_intel = MISPThreatIntel('https://misp.natas.me/', 'N1BYUwnuuqcaA',
                                 misp_verifycert=False)
    attributes = misp_intel.simple_attribute_search('217.20.116.149', 'ip-dst', timestamp='1000d')
    for attribute in attributes['Attribute']:
        print('-----------------------')
        event_detail = misp_intel.get_event_metadata(attribute['event_id'])
        print(attribute['event_id'] + ' -- ' + event_detail[0]['info'])
        print(attribute['category'] + ' -- ' + str(event_detail[0]['threat_level_id']))
