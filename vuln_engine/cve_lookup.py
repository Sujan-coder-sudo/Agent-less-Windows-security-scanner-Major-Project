import requests

def search_cve(primary_keyword, fallback_keyword=None):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def fetch(keyword):
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": 5
        }

        response = requests.get(url, params=params)
        data = response.json()

        cves = []

        if "vulnerabilities" in data:
            for item in data["vulnerabilities"]:
                cve_id = item["cve"]["id"]

                # filter recent CVEs
                year = int(cve_id.split("-")[1])
                if year >= 2015:
                    cves.append(cve_id)

        return cves[:3]

    try:
        results = fetch(primary_keyword)

        if not results and fallback_keyword:
            results = fetch(fallback_keyword)

        return results

    except Exception as e:
        print("CVE API Error:", e)
        return []
