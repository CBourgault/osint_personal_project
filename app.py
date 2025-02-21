import streamlit as st
import json
import pandas as pd
from datetime import datetime

# Import your custom scanning modules
from scan_url import submit_url, poll_scan_results
from scan_domain import get_domain_report
from scan_ip import get_ip_report

# --------------------
# Helper function to load external CSS
# --------------------
def load_css_file(css_file_path: str):
    """
    Reads the contents of a CSS file and renders it inline using Streamlit.
    """
    with open(css_file_path) as f:
        css_content = f.read()
        st.markdown(f"<style>{css_content}</style>", unsafe_allow_html=True)

# --------------------
# Additional helper functions for scanning logic
# --------------------
def format_timestamp(ts):
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts

def summarize_domain_report(report):
    data = report.get("data", {})
    attributes = data.get("attributes", {})
    
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

def summarize_ip_report(report):
    data = report.get("data", {})
    attributes = data.get("attributes", {})
    
    summary = {
        "IP": data.get("id", "N/A"),
        "Country": attributes.get("country", "N/A"),
        "Reputation": attributes.get("reputation", "N/A"),
        "AS Owner": attributes.get("as_owner", "N/A"),
        "Last Analysis Stats": attributes.get("last_analysis_stats", {})
    }
    return summary

def extract_analysis_results(report):
    attributes = report.get("data", {}).get("attributes", {})
    # Check for the key depending on the scan type.
    results = attributes.get("last_analysis_results")
    if results is None:
        results = attributes.get("results")
    if not results:
        return pd.DataFrame()
    df = pd.DataFrame.from_dict(results, orient='index')
    df.reset_index(inplace=True)
    df.rename(columns={'index': 'Engine'}, inplace=True)
    if 'engine_name' in df.columns:
        df.drop(columns=['engine_name'], inplace=True)
    return df

# --------------------
# Main Streamlit App
# --------------------
def main():
    # Load external CSS at the start
    load_css_file("custom_styles.css")

    # Initialize session state variable for navigation if not present
    if "nav" not in st.session_state:
        st.session_state["nav"] = "VirusTotal Scanner"

    # Create clickable text-like buttons in the sidebar
    if st.sidebar.button("VirusTotal Scanner"):
        st.session_state["nav"] = "VirusTotal Scanner"
    if st.sidebar.button("Other Option"):
        st.session_state["nav"] = "Other Option"

    # Main area logic
    if st.session_state["nav"] == "VirusTotal Scanner":
        st.title("VirusTotal Scanner")

        # Nested tabs for scanning options
        tab1, tab2, tab3 = st.tabs(["URL Scan", "Domain Report", "IP Scan"])

        # --- URL Scan Tab ---
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
                    attributes = results_data.get("data", {}).get("attributes", {})
                    meta = results_data.get("meta", {}).get("url_info", {})
                    stats = attributes.get("stats", {})
                    scan_date = attributes.get("date", 0)
                    submitted_url = meta.get("url", "N/A")
                    
                    st.markdown(f"**Submitted URL:** {submitted_url}")
                    st.markdown(f"**Scan Date:** {format_timestamp(scan_date)}")
                    st.markdown("**Scan Stats:**")
                    for key, value in stats.items():
                        st.markdown(f"- **{key.capitalize()}**: {value}")
                    
                    analysis_df_url = extract_analysis_results(results_data)
                    st.dataframe(analysis_df_url)
                    
                    with st.expander("Show Raw URL Scan JSON"):
                        st.json(results_data)
                except Exception as e:
                    st.error(f"An error occurred during URL scanning: {e}")

        # --- Domain Report Tab ---
        with tab2:
            st.header("Domain Report")
            user_domain = st.text_input("Enter a domain to report:", key="domain_scan")
            if st.button("Get Domain Report") and user_domain:
                try:
                    with st.spinner("Fetching domain report..."):
                        domain_report = get_domain_report(user_domain)
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
                    
                    st.subheader("Analysis Engine Results")
                    analysis_df = extract_analysis_results(domain_report)
                    st.dataframe(analysis_df)
                    
                    with st.expander("Show Full Domain Report (raw JSON)"):
                        st.json(domain_report)
                except Exception as e:
                    st.error(f"An error occurred during domain reporting: {e}")

        # --- IP Scan Tab ---
        with tab3:
            st.header("Scan an IP Address")
            user_ip = st.text_input("Enter an IPv4 or IPv6 address:", key="ip_scan")
            if st.button("Scan IP") and user_ip:
                try:
                    with st.spinner("Fetching IP report..."):
                        ip_report = get_ip_report(user_ip)
                    summary = summarize_ip_report(ip_report)
                    st.subheader("Summary")
                    st.markdown(f"**IP Address:** {summary['IP']}")
                    st.markdown(f"**Country:** {summary['Country']}")
                    st.markdown(f"**Reputation:** {summary['Reputation']}")
                    st.markdown(f"**AS Owner:** {summary['AS Owner']}")
                    st.markdown("**Last Analysis Stats:**")
                    for stat, value in summary["Last Analysis Stats"].items():
                        st.markdown(f"- **{stat.capitalize()}**: {value}")
                    
                    analysis_df_ip = extract_analysis_results(ip_report)
                    if not analysis_df_ip.empty:
                        st.subheader("Analysis Engine Results")
                        st.dataframe(analysis_df_ip)
                    
                    with st.expander("Show Full IP Report (raw JSON)"):
                        st.json(ip_report)
                except Exception as e:
                    st.error(f"An error occurred during IP scanning: {e}")

    elif st.session_state["nav"] == "Other Option":
        st.title("Other Option")
        st.write("This area is reserved for future selections.")

# --------------------
# Entry Point
# --------------------
if __name__ == "__main__":
    main()
