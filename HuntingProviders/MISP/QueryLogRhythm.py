from elasticsearch import Elasticsearch
from elasticquery import ElasticQuery, Aggregate, Query
from datetime import datetime
from datetime import timedelta
import json


class QueryLogRhythm:
    elastic_misp_mapping = {'authentihash': ['hash', 'object'],
                            'cdhash': ['hash', 'object'],
                            'domain': ['domain', 'domainOrigin', 'impactedHostName', 'originHostName'],
                            'email-dst': ['recipient'],
                            'email-reply-to': ['recipient'],
                            'email-src': ['sender'],
                            'email-subject': ['subject'],
                            'filename': ['object', 'objectName'],
                            'impfuzzy': ['hash', 'object'],
                            'imphash': ['hash', 'object'],
                            'md5': ['hash', 'object'],
                            'pehash': ['hash', 'object'],
                            'sha1': ['hash', 'object'],
                            'sha224': ['hash', 'object'],
                            'sha256': ['hash', 'object'],
                            'sha384': ['hash', 'object'],
                            'sha512': ['hash', 'object'],
                            'sha512/224': ['hash', 'object'],
                            'sha512/256': ['hash', 'object'],
                            'ssdeep': ['hash', 'object'],
                            'tlsh': ['hash', 'object'],
                            'hassh-md5': ['hash', 'object'],
                            'hasshserver-md5': ['hash', 'object'],
                            'ja3-fingerprint-md5': ['hash', 'object'],
                            'hostname': ['domain', 'domainOrigin', 'impactedHostName', 'originHostName'],
                            'http-method': ['action', 'command'],
                            'port': ['originPort', 'impactedPort'],
                            'o-port': ['originPort'],
                            'i-port': ['impactedPort'],
                            'ip-dst': ['impactedIp', 'impactedIpV6'],
                            'ip-src': ['originIp', 'originIpV6'],
                            'link': ['url'],
                            'mac-address': ['impactedMac', 'originMac'],
                            'mime-type': ['object', 'objectName', 'objectType'],
                            'mutex': ['object', 'parentProcessName', 'parentProcessPath', 'process'],
                            'named pipe': ['object', 'parentProcessName', 'parentProcessPath', 'process'],
                            'regkey': ['object', 'objectName'],
                            'target-email': ['recipient'],
                            'target-machine': ['domain', 'domainOrigin', 'impactedHostName', 'originHostName'],
                            'target-user': ['login', 'account'],
                            'uri': ['object', 'url', 'objectName'],
                            'url': ['url'],
                            'user-agent': ['userAgent'],
                            'vulnerability': ['CVE', 'object'],
                            'windows-scheduled-task': ['parentProcessName', 'parentProcessPath', 'process'],
                            'windows-service-name': ['parentProcessName', 'parentProcessPath', 'process',
                                                     'serviceName'],
                            'test': 'test',
                            'test2': 9200,
                            'windows-service-displayname': ['parentProcessName', 'parentProcessPath', 'process',
                                                            'serviceName']}

    def __init__(self, elastic_host='localhost', elastic_port=9200):
        self.elastic_host = elastic_host
        self.elastic_port = elastic_port
        self.elastic_client = Elasticsearch([{'host': 'argos.natashell.me', 'port': 9200}])

    def build_query(self, parameters):
        if parameters is None:
            return None

        lst_and_qry = list()
        for parameter in parameters:
            data = parameters[parameter]
            terms = self.elastic_misp_mapping[parameter]
            lst_or_qry = list()
            for term in terms:
                if isinstance(data, list):
                    for value in data:
                        qry = term + ':' + str(value)
                        lst_or_qry.append(qry)
                else:
                    qry = term + ': ' + str(data)
                    lst_or_qry.append(qry)
            or_qyr = ' OR '.join(lst_or_qry)
            lst_and_qry.append('(' + or_qyr + ')')

        and_qry = ' AND '.join(lst_and_qry)
        return and_qry

    def query_ec(self, str_query, q_fields, start_date=0, end_date=0, index='logs-*', doc_type='logs',
                 hours=24, debug=False):
        if start_date > end_date:
            raise Exception('The start_date can\'t be greater than the end_date')

        if start_date == 0 or end_date == 0:
            dt_end_date = datetime.now().timestamp()
            dt_start_date = (datetime.now() - timedelta(hours=hours)).timestamp()
            start_date = int(dt_start_date) * 1000
            end_date = int(dt_end_date) * 1000

        # print(str(start_date) + ' -- ' + str(end_date))

        elastic_qry = ElasticQuery(es=self.elastic_client, index=index, doc_type=doc_type)
        elastic_qry.query(
            Query.bool(
                must=[Query.query_string(str_query),
                      Query.range('normalDate', gte=start_date, lte=end_date)]
            )
        )

        elastic_qry.aggregate(
            Aggregate.date_histogram('2', 'normalDate', '12h')
        )

        my_qry = elastic_qry.dict()
        my_qry['stored_fields'] = q_fields

        search_arr = list()
        header_qry = {"index": ["logs-*"], "ignore_unavailable": True}
        search_arr.append(header_qry)
        search_arr.append(my_qry)

        print('Elastic Query: ' + str(search_arr))
        print('------------------------------------------------------------------------------------')
        print('Lucene Query: ' + str_query)

        request = ''
        for each in search_arr:
            request += '%s \n' % json.dumps(each)

        # print(request)

        resp = self.elastic_client.msearch(body=request)

        if resp is None and len(resp['responses']) <= 0:
            return None
        else:
            response = resp['responses'][0]
            hits_data = list()
            if response['hits']['total'] > 0:
                for hit in response['hits']['hits']:
                    hits_data.append(hit)

        # print(str(hits_data))

        return search_arr, hits_data


if __name__ == '__main__':
    ec = QueryLogRhythm(elastic_host='argos.natashell.me')
    datos = {'ip-dst': '172.217.7.35'}

    #datos = {'md5': ['65674DB003381B328431D8ABD0E2E8F3E845EA3B', '65674DB003381B328431D8ABD0E2E8F3E845EA3B']}
    #         'ip-dst': ['172.217.6.142'], 'filename': ['test.exe']}
    query = ec.build_query(datos)
    print(query)
    fields = list()
    fields.append('originIp')
    fields.append('originHostName')
    fields.append('commonEventName')
    fields.append('msgClassName')
    fields.append('impactedIp')
    fields.append('logMessage')
    fields.append(' logSourceName')
    query, hits = ec.query_ec(query, fields, debug=True, hours=900)
    print(json.dumps(query, indent=4))
    print(json.dumps(hits, indent=4))
