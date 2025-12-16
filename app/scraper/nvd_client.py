import urllib.request, urllib.parse, urllib.error
import json
# import ssl

# # api_key = False

# # if (api_key == False):

# #     api_key = "3659d776-1785-40e7-b75a-f44ab45b271b"
# serviceUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Microsoft"

# # "https://services.nvd.nist.gov/rest/json/cves/2.0/?KeywordSearch=Microsoft"

# #     api_key = ""
serviceUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=1&startIndex=0"


# param = ""

# fhand = urllib.request.urlopen(serviceUrl)

# data = dict()

# data = fhand.read().decode()

# js = json.loads(data)

# with open("data_file.json", "w") as file:
#     # json.dump(data, json_file, indent=4)
#     file.write(data)


with urllib.request.urlopen(serviceUrl) as response:
    raw_data = response.read()
    data = json.loads(raw_data)

    cve_data = data["vulnerabilities"][0]["cve"]

    cve_id = cve_data["id"]
    cve_description = cve_data["descriptions"][0]["value"]
    severity = cve_data["metrics"]["cvssMetricV2"][0]["baseSeverity"]
    exploit_score = cve_data["metrics"]["cvssMetricV2"][0]["exploitabilityScore"] 

    print("Vulnerabilit ID: ", cve_id)
    print("Vulnerability Description: ", cve_description)
    print("Severity: ",severity)
    print("Expoitability Score: ", exploit_score)