from pymisp import PyMISP
import enum


class WarnListFilter(enum.Enum):
    All = 0
    Enabled = 1
    Disabled = 2


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
        self.misp_intel = PyMISP(self.misp_url, self.misp_key, self.misp_verifycert, debug)

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

    def get_warnlists(self, filter : WarnListFilter = WarnListFilter.All):
        result = self.misp_intel.warninglists()
        f_enable = True
        if filter == WarnListFilter.All:
            return result
        elif filter == WarnListFilter.Enabled:
            f_enable = True
        else:
            f_enable = False

        new_list = list()
        for item in result:
            if item['Warninglist']['enabled'] == f_enable:
                new_list.append(item)
        return new_list

    def get_warnlist_items(self, warnlist):
        result = self.misp_intel.get_warninglist(warnlist)
        if result is None:
            raise Exception('MISP Threat Intelligence didn\'t response correctly')
        return result['Warninglist']['WarninglistEntry']


if __name__ == '__main__':
    misp_intel = MISPThreatIntel('https://hermes.natas.me/', 'CX4Op2F8vXzBzumivf6',
                                 misp_verifycert=False, debug=False)
    #lists = misp_intel.get_warnlists(filter=WarnListFilter.Disabled)
    values = misp_intel.get_warnlist_items(42)
    print('len: ' + str(len(values)))
    print(str(values))
