import yaml
import argparse
import json
import time
from cortex4py.api import Api
from cortex4py.query import *


# TODO: Gather parameters from config file (YAML)
class CortexHuntingProvider:

    lr_cortex_mapping = {'': '', }

    def __init__(self, config_file='C:\\automation-hunting\\cortex\\conf\\cortex-provider.yaml'):

        self.cortex_url = None
        self.api_key = None
        self.analyzers = list()
        self.auto_analyzers_discovery = False
        self.cleanup = False

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

    def run_analyzer_by_id(self, ioc, data_type, analyze_id):
        observable = {'data': ioc, 'dataType': data_type}
        job = self.api.analyzers.run_by_id(analyze_id, observable)
        time.sleep(5)
        report = self.api.jobs.get_report_async(job.id).report
        print(str(report))
        artifacts = self.api.jobs.get_artifacts(job.id)

        print('Job {} has generated the following artifacts:'.format(job.id))
        for a in artifacts:
            print('- [{}]: {}'.format(a.dataType, a.data))

        return report, job

    def run_analyzer_by_name(self, ioc, data_type, analyze_name):
        observable = {'data': ioc, 'dataType': data_type}
        job = self.api.analyzers.run_by_name(analyze_name, observable)
        time.sleep(5)
        report = self.api.jobs.get_report_async(job.id).report
        print(str(report))
        artifacts = self.api.jobs.get_artifacts(job.id)

        print('Job {} has generated the following artifacts:'.format(job.id))
        for a in artifacts:
            print('- [{}]: {}'.format(a.dataType, a.data))

        return report, job

    def delete_all_jobs(self):
        query = Eq('status', 'Success')
        jobs = self.api.jobs.find_all(query, range='0-100', sort='-createdAt')
        for job in jobs:
            self.api.jobs.delete(job.id)

    def delete_job(self, job_id):
        self.api.jobs.delete(job_id)

    def print_analyzers(self):
        for analyzer in self.analyzers:
            print(json.dumps(analyzer.__dict__, indent=4))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='LogRhythm CORTEX ThreatHunting Provider')
    parser.add_argument('--config', required=True, default='C:\\automation-hunting\\cortex\\conf\\cortex-provider.yaml',
                        help='CORTEX Hunting Provider Configuration File')

    args = parser.parse_args()
    crx = CortexHuntingProvider(config_file=args.config)
    crx.run_analyzer_by_id('D058F952EA2EF4A44EA738E907CF5FEB9A2F4F33', 'hash', 'e74e6c717add97f92ab83953d34b7d67')
    # crx.delete_jobs()
