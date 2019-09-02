import time
import yaml
from CaseProviders.LogRhythm.LogRhythmCaseManagement import *
from CaseProviders.LogRhythm.LogRhythmAlarmManagement import *
from CaseProviders.MISP.MISPCaseManagement import *
from CaseProviders.TheHive.HiveManagement import *

def CaseDaemon():



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
        if 'logrhythm' not in cfg or 'misp' not in cfg or 'hive' not in cfg:
            return False
        return True

if __name__ == '__main__':
    print('start')
    lr_case = LogRhythmCaseManagement('https://lr.apigw.me:8501', 'eyJhbGciOiJSUzsInR5cCI6IkpXVCJ9.eyJ1aWQi')

    response = lr_case.get_all_cases([1, 3], 36000)
    print(str(response))
