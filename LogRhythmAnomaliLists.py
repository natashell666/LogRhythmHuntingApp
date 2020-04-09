from ThreatIntellProviders.Anomali.AnomaliThreatIntel import AnomaliThreatIntel
import argparse
import os
import time


def save_threat_intel(anomali_object, file_name, anomali_type, risk_value):
    list_file = open(file_name, 'w', encoding='utf-8')
    anomali_values = anomali_object.get_intel_type(anomali_type, risk_value)
    for value in anomali_values:
        print(str(value['value'].encode("utf-8"), 'utf-8'), file=list_file)
    list_file.close()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Generic Anomali to LogRhythm Threat Intel')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help='Get all the IP in anomaly', action='store_const', dest='flag', const='ip')
    group.add_argument("--hash", help='Get all the Hashes in anomaly', action='store_const', dest='flag', const='hash')
    group.add_argument("--domain", help='Get all the Domains in anomaly', action='store_const', dest='flag',
                       const='domain')
    group.add_argument("--url", help='Get all the URL\'s in anomaly', action='store_const', dest='flag', const='url')
    group.add_argument("--service_name", help='Get all the Services in anomaly', action='store_const', dest='flag',
                       const='service_name')
    group.add_argument("--email_address", help='Get all the E-Mails address in anomaly', action='store_const',
                       dest='flag', const='email_address')
    group.add_argument("--serial", help='Get all the serials in anomaly', action='store_const', dest='flag',
                       const='serial')
    group.add_argument("--process_name", help='Get all the Process Name in anomaly', action='store_const', dest='flag',
                       const='process_name')
    group.add_argument("--process_path", help='Get all the Process Path in anomaly', action='store_const', dest='flag',
                       const='process_path')
    group.add_argument("--user_agent", help='Get all the User Agents in anomaly', action='store_const', dest='flag',
                       const='user_agent')
    group.add_argument("--subject", help='Get all the Email Subjects in anomaly', action='store_const', dest='flag',
                       const='subject')
    group.add_argument("--file_path", help='Get all the File Paths in anomaly', action='store_const', dest='flag',
                       const='file_path')
    group.add_argument("--file_name", help='Get all the File Names in anomaly', action='store_const', dest='flag',
                       const='file_name')
    group.add_argument("--registry_key", help='Get all the Registry Keys in anomaly', action='store_const', dest='flag',
                       const='registry_key')
    group.add_argument("--mutex", help='Get all the Mutex in anomaly', action='store_const', dest='flag', const='mutex')
    group.add_argument("--malware_ip", help='Get all the Malware IP\'s in anomaly', action='store_const', dest='flag',
                       const='malware_ip')
    group.add_argument("--cryto_ip", help='Get all the Crypto Mining IP\'s in anomaly', action='store_const',
                       dest='flag', const='crypto_ip')
    group.add_argument("--security_ip", help='Get all the Security IP\'s in anomaly', action='store_const', dest='flag',
                       const='security_ip')
    group.add_argument("--spam_ip", help='Get all the Spam IP\'s in anomaly', action='store_const', dest='flag',
                       const='spam_ip')
    group.add_argument("--ddos_ip", help='Get all the DDOS IP\'s in anomaly', action='store_const', dest='flag',
                       const='ddos_ip')
    group.add_argument("--suspicious_ip", help='Get all the Suspicious IP\'s in anomaly', action='store_const',
                       dest='flag', const='suspicious_ip')
    group.add_argument("--proxy_ip", help='Get all the Proxy IP\'s in anomaly', action='store_const', dest='flag',
                       const='proxy_ip')
    group.add_argument("--vpn_ip", help='Get all the VPN IP\'s in anomaly', action='store_const', dest='flag',
                       const='vpn_ip')
    group.add_argument("--tor_ip", help='Get all the TOR IP\'s in anomaly', action='store_const', dest='flag',
                       const='tor_ip')
    group.add_argument("--malware_domain", help='Get all the Malware Domains in anomaly', action='store_const',
                       dest='flag', const='malware_domain')
    group.add_argument("--security_domain", help='Get all the Security Domains in anomaly', action='store_const',
                       dest='flag', const='security_domain')
    group.add_argument("--spam_domain", help='Get all the Spam Domains in anomaly', action='store_const', dest='flag',
                       const='spam_domain')
    group.add_argument("--suspicious_domain", help='Get all the Suspicious Domains in anomaly', action='store_const',
                       dest='flag', const='suspicious_domain')
    group.add_argument("--proxy_domain", help='Get all the Proxy Domains in anomaly', action='store_const', dest='flag',
                       const='proxy_domain')
    group.add_argument("--vpn_domain", help='Get all the VPN Domains in anomaly', action='store_const', dest='flag',
                       const='vpn_domain')
    group.add_argument("--adware_domain", help='Get all the Adware Domains in anomaly', action='store_const',
                       dest='flag', const='adware_domain')
    group.add_argument("--all", help='Get all the Threat Intelligence available in anomaly', action='store_const',
                       dest='flag', const='all')

    parser.add_argument("UserName", help='Name of the file name where we will save the intelligence list')
    parser.add_argument("Anomali_API_Key", help='Name of the file name where we will save the intelligence list')
    parser.add_argument('--risk', type=int, help='Minimum Risk Score to get', default=90)
    parser.add_argument('--sleep', type=int, help='Time in seconds to wait between requests to Anomali in case of all',
                        default=2)

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument("--api", help='Use the API to send update the lists in LogRhythm', dest='mode',
                            action='store_const', const='api')
    mode_group.add_argument("--list", help='Use the LogRhythm JobMgr Directory to update the lists in LogRhythm',
                            dest='mode', action='store_const', const='list')

    list_group = parser.add_argument_group(title='LogRhythm List options')
    list_group.add_argument("--list_name", help='Name of the file name or list where we will save the intelligence list'
                            , default='anomali.lst')
    list_group.add_argument("--list_directory", help='Directory where the Job Manager gets the auto-import lists',
                            default='C:\\Program Files\\LogRhythm\\LogRhythm Job Manager\\config\\list_import')

    api_group = parser.add_argument_group(title='LogRhythm API options')
    api_group.add_argument("--lr_api_key", help='LogRhythm API Key')

    args = parser.parse_args()

    if args.mode == 'api' and not args.lr_api_key:
        parser.error('The --api argument requires the --lr_api_key parameter set')

    anomali = AnomaliThreatIntel(args.UserName, args.Anomali_API_Key, 10000)
    file_path = os.path.join(args.list_directory, args.list_name)

    if args.mode == 'list':
        if args.flag == 'all':
            all_intel_list = ['hash', 'url', 'service_name', 'email_address', 'serial', 'process_name', 'process_path',
                              'user_agent', 'subject', 'file_path', 'file_name', 'registry_key', 'mutex', 'malware_ip',
                              'crytp_ip', 'security_ip', 'spam_ip', 'ddos_ip', 'suspicious_ip', 'proxy_ip', 'vpn_ip',
                              'tor_ip', 'malware_domain', 'security_domain', 'spam_domain', 'suspicious_domain',
                              'proxy_domain', 'vpn_domain', 'adware_domain']

            for intel_type in all_intel_list:
                file_convension = 'anomali_' + intel_type + '.lst'
                file_path = os.path.join(args.list_directory, file_convension)
                print('Getting ' + intel_type + ' into ' + file_path)
                save_threat_intel(anomali, file_path, intel_type, args.risk)
                time.sleep(args.sleep)
        else:
            save_threat_intel(anomali, file_path, args.flag, args.risk)

    # EjemplO:
    # python.exe LogRhythmAnomaliLists.py 'user@logrhythm.com' fffffffffffffffffffffffffffffffffffffffffffffff
    # --all --list_directory=C:\Users\natas\Anomali_test --risk 0 --list
