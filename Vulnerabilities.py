from datetime import datetime, timedelta
import requests
import json

# Print functions are for debugging
# List of keywords, using as tags for vulnerability searching
list_keywords = []
anomali_apikey = ""
ms_teams_webhook = ""
days_relevancy = int()

# Time relevancy hours calculator
last_24_hours = (datetime.now() - timedelta(days=days_relevancy)).strftime('%Y-%m-%dT%H:%M:%S')

list_appended_ids = []


# Func for requesting Vulerability IDs
def http_req_vulns(keyword):
    headers = {'Authorization': f'apikey {anomali_apikey}'}
    response = requests.get(
        'https://api.threatstream.com/api/v1/threat_model_search/'
        '?limit=10&model_type=vulnerability&value={}&created_ts__gt={}'.format(keyword, last_24_hours), headers=headers)
    # print(response.json())
    return response.json()


# Func for requesting full information about vulnerabilities
def http_req_ids_full(data):
    headers = {'Authorization': f'apikey {anomali_apikey}'}
    response = requests.get(
        'https://api.threatstream.com{}'.format(data), headers=headers)
    return response.json()


# Func for creating IDs list for further requests
def create_vulns_ids():
    for i in list_keywords:
        ready = http_req_vulns(i)
        if len(ready['objects']) == 0:
            pass
        else:
            for b in ready['objects']:
                list_appended_ids.append(b['resource_uri'])
    create_vulns_info()


# Func for finalizing Vulns Info
def create_vulns_info():
    buildready = []
    for i in set(list_appended_ids):
        ready_id = http_req_ids_full(i)
        if ready_id['name'].startswith('CVE'):
            buildready.append({'name': ready_id['name'], 'value': ready_id['description'].replace('\'', ' ').replace('\"', ' ')})
        else:
            pass
    create_final_list(buildready)


# Creating and clearing final JSON formatted file
def create_final_list(data):
    str_clearing = (str(data).replace('\'', "\""))
    json_final = json.loads(str_clearing)
    teams_mes(json_final)


# Sending to MS Teams as notification
def teams_mes(data):
    headers = {'Content-Type': 'application/json'}
    template = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": "FF0000",
                "summary": "New Vulnerabilies Since Yesterday",
                "sections": [{
                    "activityTitle": "New Vulnerabilities for last 3 days",
                    "facts": data}]
                }
    response = requests.post(
        ms_teams_webhook, headers=headers, data=json.dumps(template))
    print(response)


create_vulns_ids()
