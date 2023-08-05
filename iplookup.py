import requests
from ipwhois import IPWhois
from shodan import Shodan

VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_API_KEY"
SHODAN_API_KEY = "YOUR_SHODAN_API_kEY"

def get_virustotal_data(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return None

def get_virustotal_ip_url(ip):
    return f"https://www.virustotal.com/gui/ip-address/{ip}"

def get_virustotal_connected_url_url(ip, url_hash):
    return f"https://www.virustotal.com/gui/url/{url_hash}/detection"

def main():
    ip_address = input("Enter the IP address to look up: ")

    print("\n=== VIRUSTOTAL.COM ===")
    virustotal_data = get_virustotal_data(ip_address)
    if virustotal_data:
        attributes = virustotal_data["data"]["attributes"]

        # Print basic information about the IP address
        print("IP Address:", ip_address)
        print("Asn:", attributes.get("asn"))
        print("Continent:", attributes.get("continent"))
        print("Country:", attributes.get("country"))
        print("Longitude:", attributes.get("longitude"))
        print("Latitude:", attributes.get("latitude"))

        # Print information about detections and engines
        print("Positive Detections:", attributes["last_analysis_stats"].get("malicious", 0))
        print("Total Engines:", attributes["last_analysis_stats"].get("total", 0))

        # Print information about recent resolutions for the IP address
        resolutions = attributes.get("resolutions", [])
        if resolutions:
            print("\nRecent Resolutions:")
            for resolution in resolutions:
                print("Date:", resolution["last_resolved"])
                print("Hostname:", resolution["hostname"])
                print("Response:", resolution["response"])
                print("=====")

        # Print information about connected URLs and their positives
        connected_urls = attributes.get("last_https_certificate_info", {}).get("connected_urls", [])
        if connected_urls:
            print("\nConnected URLs:")
            for url_info in connected_urls:
                print("URL:", url_info["url"])
                print("Positive Detections:", url_info["positives"])
                print("Total Engines:", url_info["total"])
                print("=====")

        # Print more information as needed from the VirusTotal API response

    else:
        print("Failed to retrieve data from virustotal.com.")

    
    if __name__ == "__main__":
        main()
    
    
    else:
        print("Failed to retrieve data from virustotal.com.")


def get_whois_data(ip):
    try:
        ipwhois = IPWhois(ip)
        result = ipwhois.lookup_rdap(depth=1)
        return result
    except Exception as e:
        print("Error fetching WHOIS data:", e)
        return None
        
def get_abuseipdb_data(ip):
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {
        "Key": ABUSEIPDB_API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        return data
    else:
        return None

def get_shodan_data(ip):
    try:
        shodan_api = Shodan(SHODAN_API_KEY)
        result = shodan_api.host(ip)
        return result
    except Exception as e:
        print("Error fetching Shodan data:", e)
        return None
        
def main():
    ip_address = input("Enter the IP address to look up: ")

    print("\n=== WHOIS.DATA ===")
    whois_data = get_whois_data(ip_address)
    if whois_data:
        # Handle ASN information
        asn_info = whois_data.get("asn")
        if isinstance(asn_info, dict):
            print("ASN Description:", asn_info.get("description", "N/A"))
            print("ASN Country:", asn_info.get("country", "N/A"))
        else:
            print("ASN Information not available.")

        # Handle Network information
        network_info = whois_data.get("network")
        if isinstance(network_info, dict):
            print("Network Name:", network_info.get("name", "N/A"))
            print("Network Handle:", network_info.get("handle", "N/A"))
            print("CIDR:", network_info.get("cidr", "N/A"))
            print("Start Address:", network_info.get("startAddress", "N/A"))
            print("End Address:", network_info.get("endAddress", "N/A"))
        else:
            print("Network Information not available.")
    
    print("\n=== VIRUSTOTAL.COM ===")
    virustotal_data = get_virustotal_data(ip_address)
    if virustotal_data:
        attributes = virustotal_data["data"]["attributes"]

        # Print basic information about the IP address
        print("IP Address:", ip_address)
        print("Asn:", attributes.get("asn"))
        print("Asn Name:", attributes.get("asn_name"))
        print("Asn Type:", attributes.get("asn_type"))
        print("Continent:", attributes.get("continent"))
        print("Country:", attributes.get("country"))
        print("Longitude:", attributes.get("longitude"))
        print("Latitude:", attributes.get("latitude"))

        # Print information about detections and engines
        print("Positive Detections:", attributes["last_analysis_stats"].get("malicious", 0))
        print("Total Engines:", attributes["last_analysis_stats"].get("total", 0))

        # Print information about recent resolutions for the IP address
        resolutions = attributes.get("resolutions", [])
        if resolutions:
            print("\nRecent Resolutions:")
            for resolution in resolutions:
                print("Date:", resolution["last_resolved"])
                print("Hostname:", resolution["hostname"])
                print("Response:", resolution["response"])
                print("=====")

        # Print information about connected URLs and their positives
        connected_urls = attributes.get("last_https_certificate_info", {}).get("connected_urls", [])
        if connected_urls:
            print("\nConnected URLs:")
            for url_info in connected_urls:
                print("URL:", url_info["url"])
                print("Positive Detections:", url_info["positives"])
                print("Total Engines:", url_info["total"])
                print("=====")

        # Print more information as needed from the VirusTotal API response

    else:
        print("Failed to retrieve data from virustotal.com.")

    print("\n=== ABUSEIPDB.COM ===")
    abuseipdb_data = get_abuseipdb_data(ip_address)
    if abuseipdb_data:
        print("IP Address:", abuseipdb_data["data"]["ipAddress"])
        print("Abuse Confidence Score:", abuseipdb_data["data"]["abuseConfidenceScore"])
        print("Country Code:", abuseipdb_data["data"]["countryCode"])
        print("ISP/Organization:", abuseipdb_data["data"]["isp"])
        print("Usage Type:", abuseipdb_data["data"]["usageType"])
        print("Domain Name:", abuseipdb_data["data"]["domain"])
        print("Total Reports:", abuseipdb_data["data"]["totalReports"])
        print("Last Reported Date:", abuseipdb_data["data"]["lastReportedAt"])
    else:
        print("Failed to retrieve data from abuseipdb.com.")

    print("\n=== SHODAN ===")
    shodan_data = get_shodan_data(ip_address)
    if shodan_data:
        print("IP Address:", shodan_data.get("ip_str", "N/A"))
        print("Organization:", shodan_data.get("org", "N/A"))
        print("Operating System:", shodan_data.get("os", "N/A"))
        print("Ports:")
        for port_info in shodan_data.get("ports", []):
            print(f"- Port: {port_info}")
        print("=====")
        # Print more information as needed from the Shodan API response
    else:
        print("Failed to retrieve data from Shodan.")

if __name__ == "__main__":
    main()