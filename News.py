from datetime import datetime, timedelta
import requests
import json
import re

# Print functions are for debugging
# List of keywords, using as tags for news searching
list_keywords = []
anomali_apikey = ""
ms_teams_webhook = ""
days_relevancy = int()

# Time relevancy hours calculator
last_24_hours = (datetime.now() - timedelta(days=days_relevancy)).strftime('%Y-%m-%dT%H:%M:%S')

list_appended_ids = []


# Func for requesting News IDs
def http_req_news(keyword):
    headers = {'Authorization': f'apikey {anomali_apikey}'}
    response = requests.get(
        'https://api.threatstream.com/api/v1/threat_model_search/'
        '?limit=10&model_type=tipreport&value={}&created_ts__gt={}'.format(keyword, last_24_hours), headers=headers)
    # print(response.json())
    return response.json()


# Func for requesting full information about news
def http_req_ids_full(data):
    headers = {'Authorization': f'apikey {anomali_apikey}'}
    response = requests.get(
        'https://api.threatstream.com{}'.format(data), headers=headers)
    return response.json()


# Func for creating IDs list for further requests
def create_news_ids():
    for i in list_keywords:
        ready = http_req_news(i)
        if len(ready['objects']) == 0:
            pass
        else:
            for b in ready['objects']:
                list_appended_ids.append(b['resource_uri'])
    print(list_appended_ids)
    create_news_info()


# Func for finalizing News Info
def create_news_info():
    buildready = []
    for i in set(list_appended_ids):
        ready_id = http_req_ids_full(i)
        match = re.search("(?P<url>https?://[^\s]+)", ready_id['body'])
        # Replacing ' to " for json format and building right format
        if match is not None:
            buildready.append({'type': 'TextBlock', 'separator': 'true', 'wrap': 'true',
                               'text': '[' + ready_id['name'].replace('\"', ' ').replace('\'',
                                                                                         ' ') + ']' + '(' + match.group(
                                   0).replace('\"', ' ').replace('\'', ' ') + ')'})
    # print(buildready)
    create_final_list(buildready)


# Creating and clearing final JSON formatted file
def create_final_list(data):
    str_clearing = (str(data).replace('\'', "\""))
    print(str_clearing)
    json_final = json.loads(str_clearing)
    print(json_final)
    teams_mes(json_final)


# Sending to MS Teams as notification
def teams_mes(data):
    headers = {'Content-Type': 'application/json'}
    template = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": 'null',
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "minHeight": "100px",
                    "version": "1.2",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "News and Threat Bulletins for last 24 hours",
                            "size": "large"
                        }
                    ],
                    "actions": [
                        {"type": "Action.ShowCard",
                         "title": "Show News",
                         "card": {
                             "type": "AdaptiveCard",
                             "body": data
                         }
                         }
                    ]
                }
            }
        ]
    }
    response = requests.post(
        ms_teams_webhook, headers=headers,
        data=json.dumps(template))
    print(response)
    print(response.content)


create_news_ids()
