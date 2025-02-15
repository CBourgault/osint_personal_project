import requests
import os
from dotenv import load_dotenv
import streamlit as st

load_dotenv()
api_key = os.getenv("VT_API_KEY")
if not api_key:
    raise Exception("API key not set. Please set the VT_API_KEY environment variable.")

headers = {
    "accept": "application/json",
    "x-apikey": api_key
}

@st.cache_data
def get_domain_report(domain):
    """
    Fetch a domain report from VirusTotal.
    
    Parameters:
        domain (str): The domain name to query.
    
    Returns:
        dict: The JSON response from VirusTotal.
    """
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()
