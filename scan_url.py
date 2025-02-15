import requests
import os
import time
from dotenv import load_dotenv

load_dotenv() 
api_key = os.getenv("VT_API_KEY")
if not api_key:
    raise Exception("API key not set. Please set the VT_API_KEY environment variable.")

headers = {
    "accept": "application/json",
    "x-apikey": api_key,
    "content-type": "application/x-www-form-urlencoded"
}

def submit_url(user_url):
    """Submit the URL to VirusTotal and return the analysis ID."""
    endpoint = "https://www.virustotal.com/api/v3/urls"
    payload = {"url": user_url}
    response = requests.post(endpoint, data=payload, headers=headers)
    response.raise_for_status()  # raises an error if the call failed
    response_data = response.json()
    return response_data["data"]["id"]

def poll_scan_results(analysis_id, delay=5, max_attempts=10):
    """Poll the analysis endpoint until the status changes from 'queued'
    
    Parameters:
      - analysis_id: the unique ID for the submitted scan
      - delay: time in seconds between each poll attempt
      - max_attempts: maximum number of polling attempts
    
    Returns:
      The JSON response from the API once the scan is no longer queued, or
      the latest response if still queued after max_attempts.
    """
    for attempt in range(max_attempts):
        results_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        results_response = requests.get(results_endpoint, headers=headers)
        results_response.raise_for_status()
        results_data = results_response.json()
        status = results_data.get("data", {}).get("attributes", {}).get("status", "queued")
        if status != "queued":
            return results_data
        time.sleep(delay)
    return results_data  # Return the latest response even if still queued
