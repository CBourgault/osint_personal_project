import requests
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("VT_API_KEY")
if not api_key:
    raise Exception("API key not set. Please set the VT_API_KEY environment variable.")

headers = {
    "accept": "application/json",
    "x-apikey": api_key
}

def get_ip_report(ip_address):
    """
    Fetch a report for an IPv4 or IPv6 address from VirusTotal.
    
    Parameters:
      - ip_address (str): The IP address to query.
    
    Returns:
      dict: The JSON response from VirusTotal.
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()
