import urllib.request, urllib.parse, urllib.error
import json
# import ssl

# # api_key = False

# # if (api_key == False):

# #     api_key = "3659d776-1785-40e7-b75a-f44ab45b271b"
# serviceUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=Microsoft"

# # "https://services.nvd.nist.gov/rest/json/cves/2.0/?KeywordSearch=Microsoft"

# #     api_key = ""



# param = ""

# fhand = urllib.request.urlopen(serviceUrl)

# data = dict()

# data = fhand.read().decode()

# js = json.loads(data)

# with open("data_file.json", "w") as file:
#     # json.dump(data, json_file, indent=4)
#     file.write(data)


serviceUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0/?resultsPerPage=10&startIndex=0"



def fetch_cve(base_url):
    with urllib.request.urlopen(base_url) as response:
        raw_data = response.read()
        return raw_data.decode()

def parse_data(fetched_cves):
    parsed_cves = json.loads(fetched_cves)
    return parsed_cves
    
def extract_cve_data(fetched_cves):
    fetched_cves = parse_data(fetched_cves)
    vlnr_data = fetched_cves["vulnerabilities"]  
    extracted_cves = []
    for data in vlnr_data:
        cve = data["cve"]
        cve_id = cve["id"]
        cve_description = cve["descriptions"][0]["value"]
        severity = cve["metrics"]["cvssMetricV2"][0]["baseSeverity"]
        exploit_score = cve["metrics"]["cvssMetricV2"][0]["exploitabilityScore"]
        
        extracted_cves.append(cve_id)
        extracted_cves.append(cve_description)
        extracted_cves.append(severity)
        extracted_cves.append(exploit_score)
    return extracted_cves        
    
                        
fetched_cves = fetch_cve(serviceUrl)

extracted_cves = extract_cve_data(fetched_cves)

for item in extracted_cves:
    print(item)




    # with open ("cve_data.json", "r") as file:
    #     data = file.read()
    #     data = json.loads(data)




# vlnrablty = data["vulnerabilities"][0]["cve"]

#     cve_id = vlnrablty["id"]
#     cve_description = vlnrablty["descriptions"][0]["value"]
#     severity = vlnrablty["metrics"]["cvssMetricV2"][0]["baseSeverity"]
#     exploit_score = vlnrablty["metrics"]["cvssMetricV2"][0]["exploitabilityScore"] 

#     print("Vulnerabilit ID: ", cve_id)
#     print("Vulnerability Description: ", cve_description)
#     print("Severity: ",severity)
#     print("Expoitability Score: ", exploit_score)