import urllib.request, urllib.parse, urllib.error
import json
import ssl

# api_key = False

# if (api_key == False):
#     api_key = "3659d776-1785-40e7-b75a-f44ab45b271b"
serviceUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&startIndex=0"

param = ""

fhand = urllib.request.urlopen(serviceUrl)

data = dict()

data = fhand.read().decode()

js = json.loads(data)

with open("data_file.json", "w") as json_file:
    json.dump(data, json_file, indent=4)