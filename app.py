import streamlit as st
import json
from scan_url import submit_url, poll_scan_results

st.title("VirusTotal URL Scanner")

user_url = st.text_input("Enter a URL to scan:")

if st.button("Scan URL") and user_url:
    try:
        with st.spinner("Submitting URL for analysis..."):
            analysis_id = submit_url(user_url)
        
        with st.spinner("Waiting for scan results..."):
            results_data = poll_scan_results(analysis_id)
        
        st.subheader("Scan Results")
        st.json(results_data)  # Displays the JSON data in a formatted view
    except Exception as e:
        st.error(f"An error occurred: {e}")
