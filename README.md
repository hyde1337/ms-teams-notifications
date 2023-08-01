# MS Teams Threat Notifications
Integration between Anomali and MS Teams to notify about recent news and vulnerabilities posted on Anomali via Adaptive Cards feature

---
## Components Description
**News.py** - component to fetch and push list of news

**Vulnerabilities.py** - component to fetch and push list of vulnerabilities

---
## Inputs
Required inputs to **both components** files:

**ms_teams_webhook: (str)** - MS Teams Webhook obtained from the messenger

**days_relevancy: (int)** - depth in days to look for latest news/vulnerabilities

**anomali_apikey: (str)** - Anomali API key obtained from the platform

**list_keywords: (list(str))** - keywords to search for