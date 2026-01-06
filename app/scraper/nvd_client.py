import urllib.request
import urllib.parse
import urllib.error
import json
# import ssl

# api_key = "3659d776-1785-40e7-b75a-f44ab45b271b"


class Cve:
    def __init__(self, cve_id, description, severity, exploit_score):
        self.cve_id = cve_id
        self.description = description
        self.severity = severity
        self.exploit_score = exploit_score

    def __repr__(self):
        data = f"Cve ID: {self.cve_id}\nDescription: {self.description}\nSeverity: {self.severity}\nExploit Score: {self.exploit_score}"
        return data


end_point = "https://services.nvd.nist.gov/rest/json/cves/2.0/?"


def url():
    params = dict()
    params["resultsPerPage"] = "10"
    url = end_point + urllib.parse.urlencode(params)
    return url


def fetch_cve(base_url):
    with urllib.request.urlopen(base_url) as response:
        raw_data = response.read()
        return raw_data.decode()


fetched_cves = fetch_cve(url())


def parse_data(fetched_cves):
    parsed_cves = json.loads(fetched_cves)
    return parsed_cves


def extract_cve_data(parsed_cves):

    vulnerabilities = parsed_cves["vulnerabilities"]
    extracted_cves = []
    for data in vulnerabilities:
        cve = data["cve"]
        cve_id = cve["id"]
        cve_description = cve["descriptions"][0]["value"]

        severity = "Unknown"
        exploit_score = 0.0

        metric = cve.get("metrics", {})

        if "cvssMetricV31" in metric and len(metric["cvssMetricV31"]) != 0:
            cvss_mv31 = metric["cvssMetricV31"][0]
            severity = cvss_mv31.get("baseSeverity", "unknown")
            exploit_score = cvss_mv31.get("exploitabilityScore", 0.0)

        elif "cvssMetricV2" in metric and len(metric["cvssMetricV2"]) != 0:
            severity = metric["cvssMetricV2"][0]["baseSeverity"]
            exploit_score = metric["cvssMetricV2"][0]["exploitabilityScore"]
        else:
            severity = "Unknown"
            exploit_score = 0.0

        cve_obj = Cve(cve_id, cve_description, severity, exploit_score)
        extracted_cves.append(cve_obj)
    return extracted_cves


extracted_cves = extract_cve_data(parse_data(fetched_cves))

print(extracted_cves)

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
