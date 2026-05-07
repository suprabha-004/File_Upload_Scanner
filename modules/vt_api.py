import requests
import config

def check_virustotal(file_hash):
    import requests
    import config

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": config.API_KEY}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()['data']['attributes']['last_analysis_stats']

            result = {
                "malicious": data.get("malicious", 0),
                "suspicious": data.get("suspicious", 0),
                "clean": data.get("undetected", 0)
            }

            # Add status
            if result["malicious"] > 0:
                result["status"] = "Malicious"
            elif result["suspicious"] > 0:
                result["status"] = "Suspicious"
            else:
                result["status"] = "Safe"

            return result

        else:
            return {"status": "Not Found"}

    except Exception:
        return {"status": "Error"}