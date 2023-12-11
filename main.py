import yaml
import time
import csv

import settings
import utils.log_handler as logger
log = logger.log
from utils.auth_handler import Auth
import utils.input_utils as input
import api


def get_writeup_choice(repos) -> int:
    """
    Prompts the user to select from a list of writeup repositories to export to CSV.
    Based on subsequently called functions, this will return a valid option or exit the script.

    :param repos: List of repostories returned from the POST List All Writeup Repositories endpoint
    :type repos: list[repository objects]
    :return: 0-based index of selected repo from the list provided
    :rtype: int
    """
    log.info(f'List of Writeup Repositories (repos with no writeups are not listed):')
    index = 1
    for repo in repos:
        log.info(f'{index} - Name: {repo["name"]} - Type: {repo["repositoryType"]} - Num Writeups: {repo["writeupsCount"]}')
        index += 1
    return input.user_list("Select a repository to export", "Invalid choice", len(repos)) - 1

def get_all_writeup_custom_fields(writeups) -> list[str]:
    """
    Creates a unique list of writeup custom field labels from all writeups in selected repository

    :param writeups: List of writesups from the GET List Writeups endpoint
    :type writeups: list[writeup objects]
    :return: List of custom field labels
    :rtype: list[str]
    """
    custom_fields = []
    for writeup in writeups:
        for field_key, field_data in writeup.get('fields', {}).items():
            if field_key != "scores" and field_data['label'] not in custom_fields:
                    custom_fields.append(field_data['label'])
    return custom_fields



if __name__ == '__main__':
    for i in settings.script_info:
        print(i)

    with open("config.yaml", 'r') as f:
        args = yaml.safe_load(f)

    auth = Auth(args)
    auth.handle_authentication()


    # load all repos from instance
    log.info(f'Loading Writeup Repositories from instance')
    # EXAMPLE schema of returned repositories
    #   {
    #         "description": "This is the Default Repository. Any existing Writeups have been moved to this repository.",
    #         "doc_type": "writeups_repository",
    #         "name": "Default Repository",
    #         "repositoryId": "cl0e3lc0c002318mx4y2bg3wn",
    #         "repositoryType": "OPEN",
    #         "repositoryUsers": [],
    #         "tenantId": 40632,
    #         "writeupsCount": 165
    #     }
    repos = []
    try:
        response = api._content_library.writeupsdb.list_all_writeup_repositories(auth.base_url, auth.get_auth_headers(), payload={})
        if response.has_json_response:
            repos = response.json['data']
            repos = list(filter(lambda x:not x['isDeleted'] and x["writeupsCount"]>0, repos))
            log.success(f'Loaded {len(repos)} repository(s) from instance')
    except Exception as e:
        log.exception(e)
        exit()
    log.debug(f'got repos: {repos}')


    # prompt user to select a repo for export
    while True:
        choice = get_writeup_choice(repos)
        if input.continue_anyways(f'Export {repos[choice]["writeupsCount"]} writeup(s) from \'{repos[choice]["name"]}\' to CSV?'):
            break
    selected_repo = repos[choice]


    # set file path for exported CSV
    parser_time_seconds: float = time.time()
    parser_time: str = time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime(parser_time_seconds))
    FILE_PATH = f'{selected_repo["name"]}_{parser_time}.csv'


    # get all writeups in user selected repo
    log.info(f'Getting Writeups from selected repository')
    #
    # EXAMPLE schema of returned writeups
# {
#     "createdAt": 1700090461882,
#     "createdBy": 905,
#     "description": "<p>The remote Windows host has <strong>Microsoft Server Message</strong> Block 1.0 (SMBv1) enabled. It is, therefore, affected by multiple vulnerabilities :</p><p><br>Multiple information disclosure vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of SMBv1 packets. An unauthenticated, remote attacker can exploit these vulnerabilities, via a specially crafted SMBv1 packet, to disclose sensitive information. (CVE-2017-0267, CVE-2017-0268, CVE-2017-0270, CVE-2017-0271, CVE-2017-0274, CVE-2017-0275, CVE-2017-0276)</p><p><br>Multiple denial of service vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of requests. An unauthenticated, remote attacker can exploit these vulnerabilities, via a specially crafted SMB request, to cause the system to stop responding. (CVE-2017-0269, CVE-2017-0273, CVE-2017-0280)</p><p><br>Multiple remote code execution vulnerabilities exist in Microsoft Server Message Block 1.0 (SMBv1) due to improper handling of SMBv1 packets. An unauthenticated, remote attacker can exploit these vulnerabilities, via a specially crafted SMBv1 packet, to execute arbitrary code. (CVE-2017-0272, CVE-2017-0277, CVE-2017-0278, CVE-2017-0279)</p><p><br>Depending on the host's security policy configuration, this plugin cannot always correctly determine if the Windows host is vulnerable if the host is running a later Windows version (i.e., Windows 8.1, 10, 2012, 2012 R2, and 2016) specifically that named pipes and shares are allowed to be accessed remotely and anonymously. Tenable does not recommend this configuration, and the hosts should be checked locally for patches with one of the following plugins, depending on the Windows version : 100054, 100055, 100057, 100059, 100060, or 100061.</p><p><br>The remote Windows host is affected by multiple vulnerabilities.</p>",
#     "doc_id": 64161997,
#     "doc_type": "template",
#     "fields": {
#         "custom_field_1": {
#             "label": "custom field 1",
#             "sort_order": 0,
#             "value": "<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Tincidunt praesent semper feugiat nibh sed pulvinar. Consectetur a erat nam at lectus urna duis convallis convallis. Sit amet luctus venenatis lectus. Nisl rhoncus mattis rhoncus urna neque. Iaculis nunc sed augue lacus viverra vitae congue eu. Velit scelerisque in dictum non consectetur a erat nam at. Donec enim diam vulputate ut pharetra.</p>"
#         },
#         "scores": {
#             "cvss": {
#                 "calculation": "AV:L/AC:M/Au:N/C:C/I:N/A:P",
#                 "label": "CVSS",
#                 "sort_order": 3,
#                 "value": "9.5"
#             },
#             "cvss3": {
#                 "calculation": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
#                 "label": "CVSS v3",
#                 "sort_order": 3,
#                 "value": "9.8"
#             }
#         }
#     },
#     "isDeleted": false,
#     "id": "template_64161997",
#     "repositoryId": "clp0dyinm00yg0ho7fbj3fjyo",
#     "recommendations": "",
#     "references": "",
#     "severity": "Critical",
#     "score": "",
#     "source": "Custom",
#     "tenantId": 0,
#     "title": "CSV TEST IMPORT 1",
#     "tags": [
#         "enclave_99",
#         "crown_jewel"
#     ],
#     "updatedAt": 1700090461891,
#     "writeupAbbreviation": "GRE-1",
#     "common_identifiers": {
#         "CVE": [
#             {
#                 "id": "0001",
#                 "name": "CVE-1999-0001",
#                 "year": "1999"
#             }
#         ],
#         "CWE": [
#             {
#                 "id": "787",
#                 "name": "CWE-787"
#             }
#         ]
#     },
#     "risk_score": {
#         "CVSS3_1": {
#             "overall": 3.7,
#             "subScore": {
#                 "base": 3.7,
#                 "environmental": 3.7,
#                 "temporal": 3.7
#             },
#             "vector": "AV:A/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:L"
#         }
#     }
# }
    writeups = []
    try:
        response = api._content_library._writeupsdb.writeups.list_writeups(auth.base_url, auth.get_auth_headers())
        if response.has_json_response:
            writeups = response.json
            writeups = list(filter(lambda x:x['repositoryId'] == selected_repo["repositoryId"] and not x['isDeleted'], writeups))
            log.success(f'Loaded {len(writeups)} writeup(s) from repository')
    except Exception as e:
        log.exception(e)
        exit()
    log.debug(writeups)


    # CREATE CSV
    # define headers
    headers1 = ["title", "severity", "description", "recommendations", "references", "tags"]
    custom_fields = get_all_writeup_custom_fields(writeups)
    headers2 = ["score::cvss3.1", "score::cvss3", "score::cvss", "cves", "cwes"]

    # pluck writeup data from API response and format as list for CSV
    csv_writeups = []
    for writeup in writeups:
        # tags
        tags = str(writeup.get('tags', "")).replace("[","").replace("]","").replace("'","")
        # custom fields
        custom_fields_values = []
        for label in custom_fields:
            has_custom_field = False
            for field_key, field_data in writeup.get('fields', {}).items():
                if field_data.get('label') == label:
                    custom_fields_values.append(field_data.get('value', ""))
                    has_custom_field = True
            if not has_custom_field:
                custom_fields_values.append("")
        # cvss fields
        cvss3_1 = ""
        if writeup.get('risk_score', {}).get('CVSS3_1'):
            cvss3_1_score = writeup['risk_score']['CVSS3_1']['overall']
            cvss3_1_calc = writeup['risk_score']['CVSS3_1']['vector']
            cvss3_1 = f'{cvss3_1_score}::{cvss3_1_calc}'
        cvss3 = ""
        if writeup.get('fields', {}).get('scores', {}).get('cvss3'):
            cvss3_score = writeup['fields']['scores']['cvss3'].get('value', "")
            cvss3_calc = writeup['fields']['scores']['cvss3'].get('calculation', "")
            if cvss3_score != "" or cvss3_calc != "":
                cvss3 = f'{cvss3_score}::{cvss3_calc}'
        cvss = ""
        if writeup.get('fields', {}).get('scores', {}).get('cvss'):
            cvss_score = writeup['fields']['scores']['cvss'].get('value', "")
            cvss_calc = writeup['fields']['scores']['cvss'].get('calculation', "")
            if cvss_score != "" or cvss_calc != "":
                cvss = f'{cvss_score}::{cvss_calc}'
        # CVE and CWE fields
        cves = ""
        if writeup.get('common_identifiers', {}).get('CVE'):
            cves = writeup['common_identifiers']['CVE']
            cves = list(map(lambda x: x['name'], cves))
            cves = str(cves).replace("[","").replace("]","").replace("'","")
        cwes = ""
        if writeup.get('common_identifiers', {}).get('CWE'):
            cwes = writeup['common_identifiers']['CWE']
            cwes = list(map(lambda x: x['name'], cwes))
            cwes = str(cwes).replace("[","").replace("]","").replace("'","")
        # default fields
        fields_for_csv = [
            writeup.get('title', ""),
            writeup.get('severity', ""),
            writeup.get('description', ""),
            writeup.get('recommendations', ""),
            writeup.get('references', ""),
            tags
        ]
        fields_for_csv += custom_fields_values
        fields_for_csv += [
            cvss3_1,
            cvss3,
            cvss,
            cves,
            cwes
        ]
        # add writeup to list to be written to csv
        csv_writeups.append(fields_for_csv)

    # WRITE CSV
    with open(FILE_PATH, 'w', newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers1 + custom_fields + headers2)
        writer.writerows(csv_writeups)
    log.success(f'Saved writeups to CSV \'{FILE_PATH}\'')