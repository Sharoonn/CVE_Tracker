import urllib.request, urllib.parse, urllib.error
import json
import ssl

# api_key = False

# if (api_key == False):
#     api_key = ""
serviceUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&startIndex=0"

param = ""

fhand = urllib.request.urlopen(serviceUrl)

data = dict()

data = fhand.read().decode()

js = json.loads(data)

with open("data_file.json", "w") as json_file:
    json.dump(data, json_file, indent=4)
