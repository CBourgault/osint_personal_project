import streamlit as st
import json
import pandas as pd
from datetime import datetime
from scan_url import submit_url, poll_scan_results
from scan_domain import get_domain_report

def format_timestamp(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts

def summarize_domain_report(report):
    data = report.get("data", {})
    attributes = data.get("attributes", {})
    
    # Get total votes and analysis stats from the attributes.
    total_votes = attributes.get("total_votes", {})
    analysis_stats = attributes.get("last_analysis_stats", {})

    summary = {
        "Domain": data.get("id", "N/A"),
        "Registrar": attributes.get("registrar", "N/A"),
        "Creation Date": format_timestamp(attributes.get("creation_date", 0)),
        "Last Analysis Date": format_timestamp(attributes.get("last_analysis_date", 0)),
        "Reputation": attributes.get("reputation", "N/A"),
        "Total Votes": f"Harmless: {total_votes.get('harmless', 'N/A')}, Malicious: {total_votes.get('malicious', 'N/A')}",
        "Analysis Stats": analysis_stats,
    }
    return summary

def extract_analysis_results(report):
    attributes = report.get("data", {}).get("attributes", {})
    # Check for the correct key depending on the type of scan.
    results = attributes.get("last_analysis_results")
    if results is None:
        results = attributes.get("results")
    if not results:
        return pd.DataFrame()
    # Convert the results dict into a DataFrame.
    df = pd.DataFrame.from_dict(results, orient='index')
    df.reset_index(inplace=True)
    df.rename(columns={'index': 'Engine'}, inplace=True)
    # Remove duplicate engine name if it exists.
    if 'engine_name' in df.columns:
        df = df.drop(columns=['engine_name'])
    return df

st.title("VirusTotal Scanner")

# Create two tabs: one for URL scan and one for Domain report.
tab1, tab2 = st.tabs(["URL Scan", "Domain Report"])

with tab1:
    st.header("Scan a URL")
    user_url = st.text_input("Enter a URL to scan:", key="url_scan")
    if st.button("Scan URL") and user_url:
        try:
            with st.spinner("Submitting URL for analysis..."):
                analysis_id = submit_url(user_url)
            with st.spinner("Waiting for scan results..."):
                results_data = poll_scan_results(analysis_id)
            
            st.subheader("URL Scan Results")
            # Extract stats and submitted URL info from the JSON.
            attributes = results_data.get("data", {}).get("attributes", {})
            meta = results_data.get("meta", {}).get("url_info", {})
            stats = attributes.get("stats", {})
            scan_date = attributes.get("date", 0)
            submitted_url_from_meta = meta.get("url", "N/A")
            
            st.markdown(f"**Submitted URL:** {submitted_url_from_meta}")
            st.markdown(f"**Scan Date:** {format_timestamp(scan_date)}")
            st.markdown("**Scan Stats:**")
            for key, value in stats.items():
                st.markdown(f"- **{key.capitalize()}:** {value}")
            
            # Extract and display analysis results in a table.
            analysis_df_url = extract_analysis_results(results_data)
            st.dataframe(analysis_df_url)
            
            # Optionally show the raw JSON in an expander.
            with st.expander("Show Raw URL Scan JSON"):
                st.json(results_data)
        except Exception as e:
            st.error(f"An error occurred during URL scanning: {e}")

with tab2:
    st.header("Domain Report")
    user_domain = st.text_input("Enter a domain to report:", key="domain_scan")
    if st.button("Get Domain Report") and user_domain:
        try:
            with st.spinner("Fetching domain report..."):
                domain_report = get_domain_report(user_domain)
            # Create a summary of key information.
            summary = summarize_domain_report(domain_report)
            st.subheader("Summary")
            st.markdown(f"**Domain:** {summary['Domain']}")
            st.markdown(f"**Registrar:** {summary['Registrar']}")
            st.markdown(f"**Creation Date:** {summary['Creation Date']}")
            st.markdown(f"**Last Analysis Date:** {summary['Last Analysis Date']}")
            st.markdown(f"**Reputation:** {summary['Reputation']}")
            st.markdown(f"**Total Votes:** {summary['Total Votes']}")
            st.markdown("**Analysis Stats:**")
            for stat, value in summary["Analysis Stats"].items():
                st.markdown(f"- **{stat.capitalize()}**: {value}")
            
            # Display analysis results in a table.
            st.subheader("Analysis Engine Results")
            analysis_df = extract_analysis_results(domain_report)
            st.dataframe(analysis_df)
            
            with st.expander("Show Full Domain Report (raw JSON)"):
                st.json(domain_report)
        except Exception as e:
            st.error(f"An error occurred during domain reporting: {e}")
