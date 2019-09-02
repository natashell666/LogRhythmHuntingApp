import zmq
import threading
import json
import signal
import yaml
import argparse
from datetime import datetime
from .MISPTopic import MISPEvent
from .QueryLogRhythm import QueryLogRhythm
from CaseProviders.LogRhythm.LogRhythmCaseManagement import LogRhythmCaseManagement
from ListProviders.LogRhythm.LogRhythmListManagement import LogRhythmListManagement


# TODO: Add a logger class for better output
class MISPReceiver(threading.Thread):
    misp_filters = ['misp_json_event', 'misp_json_attribute', 'misp_json', 'misp_json_sighting', 'misp_json_self']

    thread_name = 'LRMISP_Receiver'

    lr_list_misp_mapping = {'authentihash': 'MISP: Hashes', 'cdhash': 'MISP: Hashes', 'domain': 'MISP: Domains',
                            'email-dst': 'MISP: Destination Address', 'email-reply-to': 'MISP: Email Address',
                            'email-src': 'MISP: Email Address', 'email-subject': 'MISP: Subjects',
                            'filename': 'MISP: Filenames', 'impfuzzy': 'MISP: Hashes', 'imphash': 'MISP: Hashes',
                            'md5': 'MISP: Hashes', 'pehash': 'MISP: Hashes', 'sha1': 'MISP: Hashes',
                            'sha224': 'MISP: Hashes', 'sha256': 'MISP: Hashes', 'sha384': 'MISP: Hashes',
                            'sha512': 'MISP: Hashes', 'sha512/224': 'MISP: Hashes', 'sha512/256': 'MISP: Hashes',
                            'ssdeep': 'MISP: Hashes', 'tlsh': 'MISP: Hashes', 'hassh-md5': 'MISP: Hashes',
                            'hasshserver-md5': 'MISP: Hashes', 'ja3-fingerprint-md5': 'MISP: Hashes',
                            'hostname': 'MISP: Domains', 'ip-dst': 'MISP: Destination Address',
                            'ip-src': 'MISP: Source Address', 'link': 'MISP: URL', 'mime-type': 'MISP: Mime Type',
                            'mutex': 'MISP: Mutex', 'named pipe': 'MISP: Named Pipes',
                            'regkey': 'MISP: Registry Keys', 'target-email': 'MISP: Email Address',
                            'target-machine': 'MISP: Domains', 'target-user': 'MISP: Users', 'uri': 'MISP: URL',
                            'url': 'MISP: URL', 'user-agent': 'MISP: User Agent',
                            'vulnerability': 'MISP: Vulnerability', 'windows-scheduled-task': 'MISP: Process',
                            'windows-service-name': 'MISP: Process', 'windows-service-displayname': 'MISP: Process'}

    lr_list_to_data_type = {'MISP: Hashes': 'String', 'MISP: Domains': 'String',
                            'MISP: Email Address': 'String', 'MISP: Filenames': 'String',
                            'MISP: Mime Type': 'String', 'MISP: Subjects': 'String',
                            'MISP: URL': 'String', 'MISP: Mutex': 'String', 'MISP: Named Pipes': 'String',
                            'MISP: Registry Keys': 'String', 'MISP: Vulnerability': 'String',
                            'MISP: Process': 'String', 'MISP: Destination Address': 'IP', 'MISP: Source Address': 'IP',
                            'MISP: Users': 'String', 'MISP: User Agent': 'String'}

    lr_list_to_item_type = {'MISP: Hashes': 'StringValue', 'MISP: Domains': 'StringValue',
                            'MISP: Email Address': 'StringValue', 'MISP: Filenames': 'StringValue',
                            'MISP: Mime Type': 'StringValue', 'MISP: Subjects': 'StringValue',
                            'MISP: URL': 'StringValue', 'MISP: Mutex': 'StringValue',
                            'MISP: Named Pipes': 'StringValue', 'MISP: Registry Keys': 'StringValue',
                            'MISP: Vulnerability': 'StringValue', 'MISP: Process': 'StringValue',
                            'MISP: Destination Address': 'IP', 'MISP: Source Address': 'IP',
                            'MISP: Users': 'StringValue', 'MISP: User Agent': 'StringValue'}

    def __init__(self, config_file='c:\\misp-events\\conf\\misp-provider.yaml', misp_events=list(), *args, **kwargs):
        super(MISPReceiver, self).__init__(*args, **kwargs)

        self.misp_events = misp_events

        # MISP Configuration Variables
        self.misp_host = None
        self.misp_port = None
        self.misp_status = None
        self.misp_file_event = None
        self.misp_file_status = None
        self.valid_filters = None

        # ELASTIC Configuration Variables
        self.max_timeout = None
        self.search_back = None
        self.elastic_host = None
        self.fields = None

        # LogRhythm Configuration Variables
        self.lr_api_host = None
        self.lr_api_key = None
        self.lr_list = None
        self.lr_case = None
        self.lr_collaborators = None
        self.lr_owner = None
        self.status = None
        self.playbook_id = None
        self.priority = None
        self.lr_tags = None
        self.top_es_evidence = None

        if not self.get_config_data(config_file):
            raise Exception('Invalid Configuration File')

        self.context = zmq.Context()

        self.socket = self.context.socket(zmq.SUB)
        self.socket.connect("tcp://%s:%s" % (self.misp_host, self.misp_port))
        self.socket.setsockopt(zmq.SUBSCRIBE, b'')

        self.poller = zmq.Poller()
        self.poller.register(self.socket, zmq.POLLIN)

        self._stop = threading.Event()

    def start(self):
        while True:
            if self.stopped():
                return
            socks = dict(self.poller.poll(timeout=None))
            if self.socket in socks and socks[self.socket] == zmq.POLLIN:
                message = self.socket.recv()
                topic, s, m = message.decode('utf-8').partition(" ")
                if topic in self.valid_filters:
                    self.procesa(topic, s, m)

            for misp_topic in self.misp_events:
                for uuid, misp_event in misp_topic.items():
                    now_time = datetime.now().timestamp()
                    if (now_time - misp_event.start_time) >= self.max_timeout:
                        print('Send event ' + uuid + 'to LogRhythm')
                        self.send_misp_evt(misp_event)
                        self.misp_events.remove(misp_topic)

    def stop(self):
        self._stop.set()
        # self.socket.disconnect()
        print('Stopped')

    def stopped(self):
        return self._stop.isSet()

    def send_output(self, mode, message):
        # print(mode + ' - ' + self.thread_name + ' - ' + message)
        return

    def procesa(self, topic, s, m):
        if topic == 'misp_json_self':
            self.send_output('syslog', m)
            return

        # print(topic + ' --> ' + s + ' --> ' + m)
        m_json = json.loads(m)
        if topic == 'misp_json_event':
            print('Reviewing Event')
            if 'action' in m_json:
                if m_json['action'] == 'add':
                    misp_data = MISPEvent(m_json['Event'])
                    self.misp_events.append({m_json['Event']['uuid']: misp_data})

        if topic == 'misp_json_attribute':
            print('Reviewing Attribute')
            if 'action' in m_json:
                if m_json['action'] == 'add':
                    print('Add Action')
                    values = list()
                    if m_json['Attribute']['value'] is not None and len(m_json['Attribute']['value']) > 0:
                        values.append(m_json['Attribute']['value'])
                    if m_json['Attribute']['value1'] is not None and len(m_json['Attribute']['value1']) > 0:
                        values.append(m_json['Attribute']['value1'])
                    if m_json['Attribute']['value2'] is not None and len(m_json['Attribute']['value2']) > 0:
                        values.append(m_json['Attribute']['value2'])
                    unique_values = list(dict.fromkeys(values))
                    # IF THERE ARE QUEUE EVENTS, WE USE THE BUFFER TO ADD THE IOC's
                    for event in self.misp_events:
                        print('Adding Attribute to an Event')
                        if m_json['Event']['uuid'] in event:
                            uuid = m_json['Event']['uuid']
                            attr = {'type': m_json['Attribute']['type'], 'category': m_json['Attribute']['category'],
                                    'value': unique_values}
                            event[uuid].attrs.append(attr)
                            event[uuid].start_time = datetime.now().timestamp()
                            print('Added to event done')

                    # DOESN'T MATTER IF THERE'S BUFFER OR NOT, WE ADD THE ATTR AS AN LR ITEM LIST
                    print('Adding an Attribute')
                    attr_type = m_json['Attribute']['type']
                    if 'Event' in m_json:
                        event_guid = m_json['Event']['id']
                    else:
                        event_guid = -1

                    print('attribute type: ' + str(attr_type) + ' EVID: ' + event_guid)
                    if attr_type in self.lr_list_misp_mapping:
                        list_name = self.lr_list_misp_mapping[attr_type]
                        print('LIST: ' + list_name)
                        lr_lists = self.lr_list.get_lists_summary(list_name=list_name)
                        if len(lr_lists) > 0:
                            guid = lr_lists[0]['guid']
                            if m_json['Attribute']['value'] is not None and \
                                    len(m_json['Attribute']['value']) > 0:
                                self.lr_list.insert_item(guid, m_json['Attribute']['value'],
                                                         m_json['Attribute']['value'],
                                                         list_item_data=self.lr_list_to_data_type[list_name],
                                                         list_item_type=self.lr_list_to_item_type[list_name])
                            if m_json['Attribute']['value'] is not None and \
                                    len(m_json['Attribute']['value1']) > 0:
                                self.lr_list.insert_item(guid, m_json['Attribute']['value1'],
                                                         m_json['Attribute']['value1'],
                                                         list_item_data=self.lr_list_to_data_type[list_name],
                                                         list_item_type=self.lr_list_to_item_type[list_name])
                            if m_json['Attribute']['value'] is not None and \
                                    len(m_json['Attribute']['value2']) > 0:
                                self.lr_list.insert_item(guid, m_json['Attribute']['value2'],
                                                         m_json['Attribute']['value2'],
                                                         list_item_data=self.lr_list_to_data_type[list_name],
                                                         list_item_type=self.lr_list_to_item_type[list_name])

                        # WE LOOK FOR THE ITEM
                        # Si se encuentra guardar el dato (ioc, eventID, etc) en un archivo para consumirse en el AIE y
                        # marcar alguna correlacion como muchos ioc del mismo evento
                        attr_look_for = {attr_type: unique_values}
                        self.attr_on_elastic(attr_look_for, event_guid)
                    else:
                        print('LISTA NOMBRE NO ENCONTRADO')


                else:
                    print('NOT ADD ACTION')

        for i in self.misp_events:
            for key, value in i.items():
                print(key + ' -- ' + str(value.__dict__))

    def send_misp_evt(self, misp_event):
        ec = QueryLogRhythm(elastic_host=self.elastic_host)
        dict_qry = {}
        for attr in misp_event.attrs:
            if attr['type'] not in dict_qry:
                dict_qry[attr['type']] = list()
            for value in attr['value']:
                dict_qry[attr['type']].append(value)
        query = ec.build_query(dict_qry)
        print('--------')
        print('--------')
        print('--------')
        print('Query: ' + query)
        es_query, hits = ec.query_ec(query, self.fields, hours=self.search_back)
        if hits is not None and len(hits) > 0:
            print("RAISE A FUCKING CASE!!!!!!!!!!!!!!!!!!!")
            self.raise_case(misp_event, query, hits, es_query)

    def attr_on_elastic(self, attribute, event_id):
        ec = QueryLogRhythm(elastic_host=self.elastic_host)
        query = ec.build_query(attribute)
        es_query, hits = ec.query_ec(query, self.fields, hours=self.search_back)
        print('HITS: ' + str(hits))

        if hits is not None and len(hits) > 0:
            event_file = open(self.misp_file_event, 'a+', encoding='utf-8')
            for hit in hits:
                text_list = list()
                text_list.append('evtid=' + str(event_id))
                text_list.append('lucene=' + query)
                text_list.append('index= ' + hit['_index'])
                text_list.append('id= ' + hit['_id'])
                for field in self.fields:
                    if field in hit['fields'] and len(hit['fields'][field]) > 0:
                        text_list.append(field + '= ' + hit['fields'][field][0])
                    else:
                        text_list.append(field + '=')
                text_fields = ' #### '.join(text_list)
                print(text_fields, file=event_file)

    def raise_case(self, misp_event, query, hits, es_query):
        # MISP Playbook: FB6C2D39-2519-4276-95BD-EE3834D18165
        # Incident Playbook: 3BEDB5AF-2BD0-4080-BBB4-3F86F72FA799
        case_name = 'MISP Event ' + misp_event.misp_event['id'] + ' Found'
        case_summary = 'The MISP Event ' + misp_event.misp_event['id'] + ' has been found in one or more systems'
        case_summary += '\nPlease review and follow the playbook associated'
        case_external_id = misp_event.misp_event['id'] + ' - ' + misp_event.misp_event['info']
        try:
            print('CREATING CASE')
            case_response = self.lr_case.create_generic_case(case_name, case_summary, priority=self.priority,
                                                             external_id=case_external_id)
            case_uuid = case_response['id']
            case_tags = self.lr_tags.copy()
            if misp_event.misp_event['published']:
                case_tags.append('published')
            else:
                case_tags.append('unpublished')

            case_tags.append('MISP Priority ' + str(misp_event.misp_event['threat_level_id']))
            print('ADDING TAGS: ' + str(case_tags))
            for tag in case_tags:
                print('Adding tag: ' + tag)
                tag_id = self.lr_case.find_srpc_tag(tag)
                print('Adding tag: ' + tag + ' with tag_id: ' + str(tag_id))
                if tag_id == -1:
                    print('Tag not found, another created: ' + str(tag_id))
                    tag_response = self.lr_case.create_srpc_tag(tag)
                    tag_id = tag_response['number']
                self.lr_case.add_srpc_tag(tag_id, case_uuid)

            print('CHANGING OWNER')
            if self.lr_owner != 0 and self.lr_owner != int(case_response['owner']):
                self.lr_case.add_srpc_collaborator(self.lr_owner, case_uuid)
                self.lr_case.change_srpc_owner(self.lr_owner, case_uuid)

            print('ADDING COLLABORATORS')
            for collab in self.lr_collaborators:
                self.lr_case.add_srpc_collaborator(collab, case_uuid)

            print('ADDING PLAYBOOK')
            self.lr_case.add_srpc_playbook(self.playbook_id, case_uuid)

            print('ADDING THE EVENT EVIDENCE')
            note_text = list()
            note_text.append('-- MISP Event Information --')
            note_text.append('-- ID: ' + str(misp_event.misp_event['id']))
            note_text.append('-- Name: ' + str(misp_event.misp_event['info']))
            note_text.append('-- Published: ' + str(misp_event.misp_event['published']))
            note_text.append('-- Analysis: ' + str(misp_event.misp_event['analysis']))
            note_text.append('-- Threat Level: ' + str(misp_event.misp_event['threat_level_id']))
            note_text.append('----------------------------')
            self.lr_case.add_srpc_evidence_note('\n'.join(note_text), case_uuid)

            print('ADDING THE SEARCH EVIDENCE')
            note_text.clear()
            note_text.append('-- Lucene Query Executed --')
            note_text.append('-- ' + query)
            note_text.append('----------------------------')
            self.lr_case.add_srpc_evidence_note('\n'.join(note_text), case_uuid)

            note_text.clear()
            note_text.append('-- Elastic Query Executed --')
            note_text.append(json.dumps(es_query, indent=2))
            note_text.append('----------------------------')
            self.lr_case.add_srpc_evidence_note('\n'.join(note_text), case_uuid)

            print('ADDING THE RESULT EVIDENCE')
            note_text.clear()
            current_log = 1
            for hit in hits:
                if current_log > self.top_es_evidence:
                    break
                note_text.append('-- Evidence Gathered --')
                note_text.append('-- Index= ' + hit['_index'])
                note_text.append('-- ID= ' + hit['_id'])
                for field in self.fields:
                    if field in hit['fields'] and len(hit['fields'][field]) > 0:
                        note_text.append('-- ' + field + '= ' + hit['fields'][field][0])
                note_text.append('----------------------------')
                self.lr_case.add_srpc_evidence_note('\n'.join(note_text), case_uuid)
                current_log += 1
                note_text.clear()

            print('SETTING THE PRIORITY')
            self.lr_case.change_srpc_status(self.status, case_uuid)

        except Exception as ex:
            print('Error')

    def get_config_data(self, yaml_file):
        with open(yaml_file, 'r') as ymlfile:
            cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

        valid = False

        if self.validate_cfg_yml(cfg):
            # MISP Configuration Variables
            self.misp_host = cfg['misp']['misp_host']
            self.misp_port = cfg['misp']['misp_port']
            self.misp_status = cfg['misp']['misp_status']
            self.misp_file_event = cfg['misp']['misp_file_event']
            self.misp_file_status = cfg['misp']['misp_file_status']
            self.valid_filters = cfg['misp']['misp_filter']

            # ELASTIC Configuration Variables
            self.max_timeout = cfg['elastic']['max_timeout']
            self.search_back = cfg['elastic']['search_back']
            self.elastic_host = cfg['elastic']['elastic_host']
            self.fields = cfg['elastic']['fields']

            # LogRhythm Configuration Variables
            self.lr_api_host = cfg['logrhythm']['api_host']
            self.lr_api_key = cfg['logrhythm']['api_key']
            self.lr_list = LogRhythmListManagement(self.lr_api_host, self.lr_api_key)
            self.lr_case = LogRhythmCaseManagement(self.lr_api_host, self.lr_api_key)
            self.lr_collaborators = cfg['logrhythm']['colabs']
            self.lr_owner = cfg['logrhythm']['owner']
            self.status = cfg['logrhythm']['status']
            self.playbook_id = cfg['logrhythm']['playbook_id']
            self.priority = cfg['logrhythm']['priority']
            self.lr_tags = cfg['logrhythm']['tags']
            self.top_es_evidence = cfg['logrhythm']['top_es_evidence']

            valid = True
        return valid

    @staticmethod
    def validate_cfg_yml(cfg):
        if 'misp' not in cfg or 'logrhythm' not in cfg or 'elastic' not in cfg:
            print('Not main')
            return False
        else:
            if 'misp_host' not in cfg['misp'] or 'misp_port' not in cfg['misp'] or 'misp_filter' not in cfg['misp'] \
                    or 'misp_status' not in cfg['misp'] or 'misp_file_status' not in cfg['misp'] \
                    or 'misp_file_event' not in cfg['misp']:
                print('Not misp')
                return False
            if 'search_back' not in cfg['elastic'] or 'max_timeout' not in cfg['elastic'] \
                    or 'elastic_host' not in cfg['elastic'] or 'fields' not in cfg['elastic']:
                print('Not elastic')
                return False
            if 'api_host' not in cfg['logrhythm'] or 'api_key' not in cfg['logrhythm'] \
                    or 'colabs' not in cfg['logrhythm'] or 'owner' not in cfg['logrhythm'] \
                    or 'status' not in cfg['logrhythm'] or 'playbook_id' not in cfg['logrhythm'] \
                    or 'priority' not in cfg['logrhythm'] or 'tags' not in cfg['logrhythm'] \
                    or 'top_es_evidence' not in cfg['logrhythm']:
                print('Not logrhythm')
                return False

        return True


def signal_handler(sig, frame):
    global t1
    t1.stop()
    t1.join()


if __name__ == '__main__':
    global t1

    parser = argparse.ArgumentParser(description='LogRhythm MISP ThreatHunting Provider')
    parser.add_argument('--config', required=True, default='C:\\automation-hunting\\misp\\conf\\misp-provider.yaml',
                        help='MISP Hunting Provider Configuration File')
    args = parser.parse_args()

    t1 = MISPReceiver(config_file=args.config)
    signal.signal(signal.SIGINT, signal_handler)
    t1.daemon = True
    t1.start()
    t1.stop()
    t1.join()
