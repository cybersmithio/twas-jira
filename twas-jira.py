from tenable.io import TenableIO
import os
import requests
from requests.auth import HTTPBasicAuth
import json
import argparse


def retrieve_was_results(TIO_ACCESS_KEY, TIO_SECRET_KEY, TIO_WAS_CONFIG_ID, MIN_REPORTING_CVSS, jira):
    tio = TenableIO(TIO_ACCESS_KEY, TIO_SECRET_KEY)

    #List the scan history of this scan
    headers = {'content-type': "application/json"}
    results = tio.get(f'was/v2/scans', headers=headers, params={"config_id": TIO_WAS_CONFIG_ID})
    json_results = results.json()
    WAS_SCAN_ID=json_results['data'][0]['scan_id']

    #Get the results of the latest scan
    headers = {'content-type': "application/json"}
    results = tio.get(f'was/v2/scans/{WAS_SCAN_ID}/report', headers=headers)
    json_results = results.json()

    finding_count = 0
    for i in json_results['findings']:
        report = False
        if MIN_REPORTING_CVSS is None:
            report = True
        elif i['cvssv3'] is not None :
            if i['cvssv3'] >= MIN_REPORTING_CVSS:
                report=True

        if report is True:
            finding_count += 1
            #print(f"\nFinding #{finding_count}")
            #print(f"Name: {i['name']}")
            #print(f"Plugin ID: {i['plugin_id']}")
            #print(f"CVSS v3: {i['cvssv3']}")
            #print(f"Description: {i['description']}")
            #print(f"Solution: {i['solution']}")
            #print(f"Output: {i['output']}")
            jira.create_was_ticket(i)


class JiraConnection(object):
    def __init__(self):
        self.jira_api_key = None
        self.jira_domain = None
        self.jira_project = None
        self.jira_username = None
        self.dry_run = False

    def connect(self):
        url = f"https://{self.jira_domain}.atlassian.net/rest/api/3/search"
        auth = HTTPBasicAuth(self.jira_username, self.jira_api_key)
        query = {
            'jql': f'project={self.jira_project}'
        }

        headers = {
            "Accept": "application/json"
        }
        response = requests.request(
            "GET",
            url,
            headers=headers,
            params=query,
            auth=auth
        )

        self.jira_project_json = json.loads(response.text)
        issue_count = 0
        for i in self.jira_project_json['issues']:
            issue_count += 1
            #print(f"\nIssue #{issue_count}")
            #print("Issue key: ", i['key'])
            #print("Issue summary: ", i['fields']['summary'])
            #print("Issue type: ", i['fields']['issuetype']['name'])
            #print("Issue ID: ", i['fields']['issuetype']['id'])
            #try:
            #    print("Issue Description: ", i['fields']['description']['content'][0]['content'][0]['text'])
            #except:
            #    print("Issue Description: ")
        #print(json.dumps(json.loads(response.text), sort_keys=True, indent=4, separators=(",", ": ")))

    def create_was_ticket(self, was_issue):
        print(f"\nChecking for existing open JIRA bug for Tenable.io plugin {was_issue['plugin_id']} - {was_issue['description']}")
        existing_key = None
        for i in self.jira_project_json['issues']:
            #print("Examining Issue key: ", i['key'])
            #print("Issue summary: ", i['fields']['summary'])
            #print("Issue description: ", i['fields']['description'])
            #print("Issue type: ", i['fields']['issuetype']['name'])
            #print("Status: ", i['fields']['status']['name'])
            if i['fields']['issuetype']['name'] != "Bug":
                continue
            #print("Issue is a bug")
            if i['fields']['summary'].startswith("Web Application Vulnerability") is False:
                continue
            #print("Issue starts with 'Web Application Vulnerability'")
            if i['fields']['status']['name'] == "Done":
                continue
            #print("Issue is not Done")
            try:
                if i['fields']['description']['content'][0]['content'][0]['text'].startswith(f"Tenable.io WAS Plugin ID {was_issue['plugin_id']}") is False:
                    continue
            except:
                continue
            #print("Issue is the same plugin ID")
            existing_key = i['key']
            #print("Key is:", existing_key)
            break

        if existing_key is None:
            print(f"\nCreating new JIRA ticket for Tenable.io plugin {was_issue['plugin_id']} - {was_issue['name']}")
            print(f"Name: {was_issue['name']}")
            print(f"Description: {was_issue['description']}")
            print(f"CVSS v3: {was_issue['cvssv3']}")
            print(f"Solution: {was_issue['solution']}")
            print(f"Output: {was_issue['output']}")
            url = f"https://{self.jira_domain}.atlassian.net/rest/api/3/issue"
            auth = HTTPBasicAuth(self.jira_username, self.jira_api_key)
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            payload = json.dumps( {
                "update": {},
                "fields": {
                    "summary": f"Web Application Vulnerability - {was_issue['name']}",
                    "issuetype": {
                        "id": "10004"
                    },
                    "project": {
                        "key": f"{self.jira_project}"
                    },
                    "description": {
                        "type": "doc",
                        "version": 1,
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "text": f"Tenable.io WAS Plugin ID {was_issue['plugin_id']}. \n\nDescription: {was_issue['description']}\n\nSolution: {was_issue['solution']}\n\nOutput from scan: {was_issue['output']}\n\n",
                                        "type": "text"
                                    }
                                ]
                            }
                        ]
                    },
                }
            })

            if self.dry_run is False:
                response = requests.request("POST", url, data=payload, headers=headers, auth=auth)
                print("Response from JIRA API:", response)
                print("Status code from JIRA API:", response.status_code)
                print("Text from JIRA API:", response.text)
        else:
            print(f"\nUpdating existing JIRA ticket {existing_key} for Tenable.io plugin {was_issue['plugin_id']} - {was_issue['name']}")
            print(f"Name: {was_issue['name']}")
            print(f"Description: {was_issue['description']}")
            print(f"CVSS v3: {was_issue['cvssv3']}")
            print(f"Solution: {was_issue['solution']}")
            print(f"Output: {was_issue['output']}")
            #print(f"Everything: {was_issue}")


parser = argparse.ArgumentParser(description="Runs the Tenable.io WAS connector to JIRA")
parser.add_argument('--dryrun', help="Do not create or update tickets, just print what would change",action="store_true")
args = parser.parse_args()

TIO_ACCESS_KEY = os.getenv('TIO_ACCESS_KEY')
TIO_SECRET_KEY = os.getenv('TIO_SECRET_KEY')
TIO_WAS_CONFIG_ID = os.getenv('TIO_WAS_CONFIG_ID')
MIN_REPORTING_CVSS = float(os.getenv('MIN_REPORTING_CVSS'))
JIRA_API_KEY = os.getenv('JIRA_API_KEY')



jira = JiraConnection()
jira.jira_api_key = os.getenv('JIRA_API_KEY')
jira.jira_domain = os.getenv('JIRA_DOMAIN')
jira.jira_project = os.getenv('JIRA_PROJECT')
jira.jira_username = os.getenv('JIRA_USERNAME')
if args.dryrun:
    jira.dry_run = True
jira.connect()


retrieve_was_results(TIO_ACCESS_KEY, TIO_SECRET_KEY, TIO_WAS_CONFIG_ID, MIN_REPORTING_CVSS, jira)

#/was/v2/scans/5ee2b6bd-a091-4004-8779-fff669aeba75/vulnerabilities/search?limit=50&offset=0&sort=uri:desc
