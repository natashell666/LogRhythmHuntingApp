import yaml
import json
import time
import argparse
from cortex4py.api import Api
from cortex4py.exceptions import *
from cortex4py.query import *


class CortexHuntingProvider:
    lr_cortex_mapping = {'': '', }

    def __init__(self, cortex_url=None, api_key=None, auto_discovery=False, cleanup=False,
                 config_file='C:\\automation-hunting\\cortex\\conf\\cortex-provider.yaml'):

        self.cortex_url = cortex_url
        self.api_key = api_key
        self.analyzers = list()
        self.auto_analyzers_discovery = False
        self.cleanup = False

        if self.cortex_url is None or self.api_key is None:
            if not self.get_config_data(config_file):
                raise Exception('Invalid Configuration File')

        self.api = Api(self.cortex_url, self.api_key)
        self.update_analyzers_list()

    def get_config_data(self, yaml_file):
        with open(yaml_file, 'r') as ymlfile:
            cfg = yaml.load(ymlfile, Loader=yaml.FullLoader)

        valid = False

        if self.validate_cfg_yml(cfg):
            self.cortex_url = cfg['cortex']['cortex_url']
            self.api_key = cfg['cortex']['api_key']
            self.auto_analyzers_discovery = cfg['cortex']['auto_analyzers_discovery']
            self.cleanup = cfg['cortex']['cleanup']
            valid = True
        return valid

    @staticmethod
    def validate_cfg_yml(cfg):
        if 'cortex' not in cfg:
            print('Not main')
            return False
        else:
            if 'cortex_url' not in cfg['cortex'] or 'api_key' not in cfg['cortex'] \
                    or 'auto_analyzers_discovery' not in cfg['cortex'] or 'cleanup' not in cfg['cortex']:
                return False
        return True

    def update_analyzers_list(self):
        self.analyzers.clear()
        lst_analyzers = self.api.analyzers.find_all({}, range='all')
        if lst_analyzers is not None:
            for item in lst_analyzers:
                self.analyzers.append(item)

    def run_analyzer_by_id(self, ioc, data_type, analyze_id, wait_time=10, get_report=True):
        observable = {'data': ioc, 'dataType': data_type}
        job = self.api.analyzers.run_by_id(analyze_id, observable)
        report = None
        artifacts = None
        if get_report:
            time.sleep(wait_time)
            report = self.api.jobs.get_report_async(job.id).report
            artifacts = self.api.jobs.get_artifacts(job.id)
        return report, job, artifacts

    def get_report_job(self, job):
        report = self.api.jobs.get_report_async(job.id).report
        artifacts = self.api.jobs.get_artifacts(job.id)
        return report, artifacts

    def run_analyzer_by_name(self, ioc, data_type, analyze_name, wait_time=10):
        observable = {'data': ioc, 'dataType': data_type}
        job = self.api.analyzers.run_by_name(analyze_name, observable)
        time.sleep(wait_time)
        report = self.api.jobs.get_report_async(job.id).report
        artifacts = self.api.jobs.get_artifacts(job.id)
        return report, job, artifacts

    def delete_all_jobs(self):
        query = Eq('status', 'Success')
        jobs = self.api.jobs.find_all(query, range='0-100', sort='-createdAt')
        for job in jobs:
            self.api.jobs.delete(job.id)

    def delete_job(self, job_id):
        self.api.jobs.delete(job_id)

    def print_analyzers(self, basic=True):
        if basic:
            d_analyzers = self.analyzers
            for analyzer in d_analyzers:
                _analyzer = analyzer.json()
                print('{')
                print('    "id": "' + _analyzer['id'] + '",')
                print('    "name": "' + _analyzer['name'] + '",')
                print('    "createdBy": "' + _analyzer['createdBy'] + '",')
                print('    "description": "' + _analyzer['description'] + '",')
                print('    "dataTypeList": ' + str(_analyzer['dataTypeList']))
                print('}')
        else:
            for _analyzer in self.analyzers:
                print(json.dumps(_analyzer.__dict__, indent=4))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Gets an observable report from Cortex')

    subparsers = parser.add_subparsers(dest='mode', description='Mode to be used')
    subparsers.required = True

    parser_id = subparsers.add_parser('job_id')
    parser_id.add_argument('--id', help='Job ID to run', required=True)
    parser_id.add_argument('--observable', help='Observable to get the Report from', required=True)
    parser_id.add_argument('--observable_type', help='Observable Type (hash, ip, domain, url, mail, user-agent, '
                                                     'email, registry, filename, fqdn)', required=True)
    parser_name = subparsers.add_parser('job_name')
    parser_name.add_argument('--name', help='Job Name to run', required=True)
    parser_name.add_argument('--observable', help='Observable to get the Report from', required=True)
    parser_name.add_argument('--observable_type', help='Observable Type (hash, ip, domain, url, mail, user-agent, '
                                                       'email, registry, filename, fqdn)', required=True)
    parser_all = subparsers.add_parser('all_in')
    parser_all.add_argument('--observable', help='Observable to get the Report from', required=True)
    parser_all.add_argument('--observable_type', help='Observable Type (hash, ip, domain, url, mail, user-agent, '
                                                      'email, registry, filename, fqdn)', required=True)
    parser_analyzer = subparsers.add_parser('analyzers')
    parser_observable = subparsers.add_parser('observables')

    parser.add_argument('--cortex_url', help='Cortex Url', default='http://localhost:9001')
    parser.add_argument('--cortex_key', help='Cortex API Key', required=True)
    parser.add_argument('--wait_time', help='Time to wait for each analyzer', required=False, default=10)
    args = parser.parse_args()

    crx = CortexHuntingProvider(cortex_url=args.cortex_url, api_key=args.cortex_key)

    report = None
    job = None
    artifacts = None
    if args.mode == 'job_id':
        report, job, artifacts = crx.run_analyzer_by_id(args.observable, args.observable_type, args.id,
                                                        wait_time=args.wait_time)
        print('Job {} - {} was {} and has generated the following artifacts :'.format(job.id, job.analyzerName,
                                                                                      job.status))
        for artifact in artifacts:
            print('- [{}]: {}'.format(artifact.dataType, artifact.data))
        print(json.dumps(report, indent=4, sort_keys=True))

    elif args.mode == 'job_name':
        report, job, artifacts = crx.run_analyzer_by_name(args.observable, args.observable_type, args.name,
                                                          wait_time=args.wait_time)
        print('Job {} - {} was {} and has generated the following artifacts :'.format(job.id, job.analyzerName,
                                                                                      job.status))
        for artifact in artifacts:
            print('- [{}]: {}'.format(artifact.dataType, artifact.data))
        print(json.dumps(report, indent=4, sort_keys=True))

    elif args.mode == 'all_in':
        all_analyzers = list()
        for job_id in crx.analyzers:
            job_id = job_id.json()
            dataTypeList = job_id['dataTypeList']

            for dataType in dataTypeList:
                if str(args.observable_type).lower() == str(dataType).lower():
                    all_analyzers.append(job_id['id'])
                    break

        analyze_jobs = list()
        for analyzer in all_analyzers:
            try:
                report, job, artifacts = crx.run_analyzer_by_id(args.observable, args.observable_type, analyzer,
                                                                wait_time=args.wait_time, get_report=False)
                analyze_jobs.append(job)
            except InvalidInputError:
                pass
            except Exception:
                pass

        time.sleep(args.wait_time)
        for _job in analyze_jobs:
            print('Job {} - {} was {} and has generated the following artifacts :'.format(_job.id, _job.analyzerName,
                                                                                          _job.status))
            try:
                report, artifacts = crx.get_report_job(_job)
                for artifact in artifacts:
                    print('- [{}]: {}'.format(artifact.dataType, artifact.data))
                print(json.dumps(report, indent=4, sort_keys=True))
            except Exception:
                print('Error generating the report for the Job {}'.format(_job.id))

    elif args.mode == 'analyzers':
        crx.print_analyzers(basic=True)

    elif args.mode == 'observables':
        all_observables = list()
        for job_id in crx.analyzers:
            job_id = job_id.json()
            dataTypeList = job_id['dataTypeList']
            for dataType in dataTypeList:
                if dataType not in all_observables:
                    all_observables.append(str(dataType))
        print('List of Observables Types:')
        print(all_observables)

    else:
        print('Unrecognized')
