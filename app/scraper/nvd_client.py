import urllib.request, urllib.parse, urllib.error
import json
import ssl

# api_key = False

# if (api_key == False):
<<<<<<< HEAD:app/scraper/nvd_client.py
#     api_key = "3659d776-1785-40e7-b75a-f44ab45b271b"
serviceUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Microsoft"

# "https://services.nvd.nist.gov/rest/json/cves/2.0/?KeywordSearch=Microsoft"
=======
#     api_key = ""
serviceUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&startIndex=0"
>>>>>>> 75c34299d30cbde39116239ede6325d2aeeef034:scraper/nvd_fetch.py

param = ""

fhand = urllib.request.urlopen(serviceUrl)

data = dict()

data = fhand.read().decode()

js = json.loads(data)

with open("data_file.json", "w") as json_file:
    json.dump(data, json_file, indent=4)
