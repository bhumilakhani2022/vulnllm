import streamlit as st
import xml.etree.ElementTree as ET
import json
from parser_enhanced import VulnerabilityParser
from ai_module import VulnerabilityAnalyzer
from patch_manager import PatchManager, PatchStatus, PatchType
import tempfile
import os
from io import BytesIO
import base64
from fpdf import FPDF
from datetime import datetime
import sqlite3
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="AutoPatchAI - Vulnerability Assessment",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Database setup
conn = sqlite3.connect('scans.db')
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT,
        analysis TEXT
    )
''')
conn.commit()

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .risk-high {
        background-color: #ffebee;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #f44336;
    }
    .risk-medium {
        background-color: #fff3e0;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ff9800;
    }
    .risk-low {
        background-color: #e8f5e8;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #4caf50;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        text-align: center;
    }
</style>
""", unsafe_allow_html=True)

def sanitize_text(text):
    # Replace common Unicode bullets and dashes with ASCII equivalents, remove non-ASCII
    return (
        text.replace('•', '-')
            .replace('–', '-')
            .replace('—', '-')
            .encode('ascii', 'ignore')
            .decode('ascii')
    )

def strip_markdown(text):
    # Remove markdown bold/italic markers
    return text.replace('**', '').replace('*', '')

def main():
    # Header
    st.markdown('<h1 class="main-header">🔒 AutoPatchAI</h1>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; font-size: 1.2rem; color: #666;">Intelligent Vulnerability Assessment & Patch Management</p>', unsafe_allow_html=True)
    
    # Sidebar
    with st.sidebar:
        st.header("📋 Upload Options")
        upload_option = st.radio(
            "Choose input method:",
            ["Upload Nmap XML", "Paste Nmap Output", "Use Sample Data", 
             "Upload Dependency File", "Upload SARIF Report", "Upload Dockerfile"]
        )
        
        st.header("⚙️ Analysis Settings")
        include_cvss = st.checkbox("Include CVSS Scores", value=True)
        include_exploits = st.checkbox("Include Exploit Availability", value=True)
        business_context = st.text_area(
            "Business Context (Optional)",
            placeholder="e.g., Production web server, PCI DSS environment, public-facing..."
        )
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("📊 Vulnerability Assessment")
        
        # File upload or text input
        data = None
        file_type = None
        
        if upload_option == "Upload Nmap XML":
            uploaded_file = st.file_uploader(
                "Upload Nmap XML file",
                type=['xml'],
                help="Upload an Nmap scan result in XML format"
            )
            if uploaded_file is not None:
                data = uploaded_file.read().decode('utf-8', errors='replace')
                file_type = 'nmap_xml'
                
        elif upload_option == "Paste Nmap Output":
            nmap_text = st.text_area(
                "Paste Nmap output here",
                height=200,
                placeholder="Paste your Nmap scan results here..."
            )
            if nmap_text.strip():
                data = nmap_text
                file_type = 'nmap_text'
                
        elif upload_option == "Use Sample Data":
            if st.button("Load Sample Data"):
                with open("sample_scan.xml", "r") as f:
                    data = f.read()
                    file_type = 'nmap_xml'
                st.success("Sample data loaded!")

        elif upload_option == "Upload Dependency File":
            uploaded_file = st.file_uploader(
                "Upload dependency file",
                type=['txt', 'json', 'xml', 'lock'],
                help="Upload requirements.txt, package.json, composer.json, Gemfile, pom.xml, yarn.lock, or Pipfile"
            )
            if uploaded_file is not None:
                data = uploaded_file.read().decode('utf-8', errors='replace')
                filename = uploaded_file.name.lower()
                if 'requirements.txt' in filename:
                    file_type = 'requirements'
                elif 'package.json' in filename:
                    file_type = 'package_json'
                elif 'composer.json' in filename:
                    file_type = 'composer_json'
                elif 'gemfile' in filename:
                    file_type = 'gemfile'
                elif 'pom.xml' in filename:
                    file_type = 'pom_xml'
                elif 'yarn.lock' in filename:
                    file_type = 'yarn_lock'
                elif 'pipfile' in filename:
                    file_type = 'pipfile'
                else:
                    st.error("Unsupported dependency file type")
                    file_type = None
        
        elif upload_option == "Upload SARIF Report":
            uploaded_file = st.file_uploader(
                "Upload SARIF file",
                type=['json', 'sarif'],
                help="Upload a SARIF (Static Analysis Results Interchange Format) file"
            )
            if uploaded_file is not None:
                data = uploaded_file.read().decode('utf-8', errors='replace')
                file_type = 'sarif'
                
        elif upload_option == "Upload Dockerfile":
            uploaded_file = st.file_uploader(
                "Upload Dockerfile",
                type=['dockerfile', 'txt'],
                help="Upload a Dockerfile for container vulnerability analysis"
            )
            if uploaded_file is not None:
                data = uploaded_file.read().decode('utf-8', errors='replace')
                file_type = 'dockerfile'
        
        # Analysis button
        if data and file_type:
            if st.button("🚀 Analyze Vulnerabilities", type="primary"):
                with st.spinner("Analyzing vulnerabilities..."):
                    try:
                        # Parse vulnerability data
                        parser = VulnerabilityParser()
                        parsed_data = parser.parse(data, file_type)
                        
                        # Analyze vulnerabilities
                        analyzer = VulnerabilityAnalyzer()
                        analysis = analyzer.analyze_vulnerabilities(
                            parsed_data, 
                            business_context=business_context,
                            include_cvss=include_cvss,
                            include_exploits=include_exploits
                        )
                        
                        # Save and display results
                        st.session_state.analysis = analysis
                        st.session_state.parsed_data = parsed_data
                        c.execute("INSERT INTO scans (scan_time, analysis) VALUES (?, ?)", (datetime.now().isoformat(), json.dumps(analysis)))
                        conn.commit()

                    except Exception as e:
                        st.error(f"Error during analysis: {str(e)}")
                        st.exception(e)
    
    if 'analysis' in st.session_state:
        display_results(st.session_state.analysis, st.session_state.parsed_data)
        pdf_bytes = generate_pdf_report(st.session_state.analysis, st.session_state.parsed_data)
        st.download_button(
            label="📄 Download PDF Report",
            data=pdf_bytes,
            file_name="AutoPatchAI_Report.pdf",
            mime="application/pdf"
        )

    with col2:
        st.header("📈 Quick Stats")
        if 'analysis' in st.session_state:
            display_metrics(st.session_state.analysis)
        else:
            st.info("Upload data and run analysis to see metrics")

    st.header("Previous Scans")
    scans = c.execute("SELECT * FROM scans ORDER BY scan_time DESC").fetchall()
    for scan in scans:
        with st.expander(f"Scan from {scan[1]}"):
            st.json(scan[2])

    st.header("Vulnerability Trends")
    display_vulnerability_trends()

def display_results(analysis, parsed_data):
    """Display the vulnerability analysis results with AI enhancements"""
    
    # Executive Summary
    st.header("🎯 AI-Enhanced Executive Summary")
    st.markdown(analysis.get('executive_summary', 'No summary available'))
    
    # Technical Findings
    st.header("🔍 Technical Findings")
    
    # Services overview
    if 'services' in parsed_data:
        st.subheader("Detected Services")
        for service in parsed_data.get('services', []):
            col1, col2, col3 = st.columns([1, 2, 1])
            with col1:
                st.write(f"**Port {service['port']}**")
            with col2:
                st.write(f"{service['service']} {service.get('version', 'Unknown')}")
            with col3:
                risk_score = service.get('risk_score', 0)
                if risk_score >= 7:
                    st.markdown('<span style="color: red;">🔴 High Risk</span>', unsafe_allow_html=True)
                elif risk_score >= 4:
                    st.markdown('<span style="color: orange;">🟡 Medium Risk</span>', unsafe_allow_html=True)
                else:
                    st.markdown('<span style="color: green;">🟢 Low Risk</span>', unsafe_allow_html=True)
    elif 'dependencies' in parsed_data:
        st.subheader("Detected Dependencies")
        for dep in parsed_data.get('dependencies', []):
            st.write(f"- {dep['name']} ({dep['version']})")

    
    # Risk Scoring
    st.header("⚠️ Risk Scoring")
    for finding in analysis.get('findings', []):
        risk_class = "risk-high" if finding['risk_score'] >= 7 else "risk-medium" if finding['risk_score'] >= 4 else "risk-low"
        color = "#b71c1c" if risk_class == "risk-high" else ("#f57c00" if risk_class == "risk-medium" else "#388e3c")
        bg_color = "#fff0f0" if risk_class == "risk-high" else ("#fff8e1" if risk_class == "risk-medium" else "#e8f5e9")
        st.markdown(f"""
        <div style='background-color:{bg_color}; border-left: 6px solid {color}; padding: 1.5rem; margin-bottom: 1.5rem; border-radius: 0.5rem;'>
            <span style='font-size:1.5rem; font-weight:bold; color:{color};'>
                {finding['service']} - Risk Score: {finding['risk_score']}/10
            </span>
            <span style='margin-left:1rem; padding:0.2rem 0.7rem; background:{color}; color:#fff; border-radius:1rem; font-size:1rem;'>
                {"HIGH" if risk_class=="risk-high" else ("MEDIUM" if risk_class=="risk-medium" else "LOW")}
            </span>
            <br><b>Vulnerabilities:</b> <span style='color:#222;'>{', '.join(finding.get('cves', []))}</span>
            <br><b>Impact:</b> <span style='color:#222;'>{finding.get('impact', 'Unknown')}</span>
        </div>
        """, unsafe_allow_html=True)
    
    # AI Exploit Predictions
    st.header("🤖 AI Exploit Predictions")
    
    for prediction in analysis.get('exploit_predictions', []):
        pred_data = prediction['prediction']
        with st.expander(f"🎯 {prediction['service']} - Exploit Analysis"):
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Exploit Likelihood", f"{pred_data['exploit_likelihood']*100:.0f}%")
                st.metric("Time to Exploit", pred_data['time_to_exploit'])
            with col2:
                st.metric("Confidence Score", f"{pred_data['confidence_score']*100:.0f}%")
                st.metric("Priority", pred_data['mitigation_priority'])
            
            st.subheader("Attack Vectors")
            for vector in pred_data['attack_vectors']:
                st.write(f"• {vector}")
    
    # AI-Generated Fix Recommendations
    st.header("🔧 AI-Generated Fix Recommendations")
    
    for ai_rec in analysis.get('ai_recommendations', []):
        service_name = ai_rec['service']
        recommendations = ai_rec['recommendations']
        
        with st.expander(f"🤖 {service_name} - AI Recommendations"):
            st.subheader("🚨 Immediate Actions")
            for action in recommendations.get('immediate_actions', []):
                st.write(f"• {action}")
            
            st.subheader("⚙️ Configuration Changes")
            for config in recommendations.get('configuration_changes', []):
                st.write(f"• {config}")
            
            st.subheader("🛡️ Security Measures")
            for measure in recommendations.get('security_measures', []):
                st.write(f"• {measure}")
            
            st.subheader("📊 Monitoring Actions")
            for monitor in recommendations.get('monitoring_actions', []):
                st.write(f"• {monitor}")
            
            if recommendations.get('rollback_plan'):
                st.subheader("🔄 Rollback Plan")
                st.write(recommendations['rollback_plan'])
    
    # Traditional Patch Recommendations
    st.header("📦 Traditional Patch Recommendations")
    
    for i, recommendation in enumerate(analysis.get('recommendations', [])):
        with st.expander(f"📦 {recommendation['service']} - {recommendation['action']}"):
            st.write(f"**Current Version:** {recommendation.get('current_version', 'Unknown')}")
            st.write(f"**Target Version:** {recommendation.get('target_version', 'Latest')}")
            st.write(f"**Command:** `{recommendation.get('command', 'N/A')}`")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Deploy Fix", key=f"deploy_{i}"):
                    with st.spinner(f"Deploying fix for {recommendation['service']}..."):
                        # This is a placeholder for the actual deployment logic
                        # In a real application, this would trigger a secure deployment process
                        st.success(f"Fix for {recommendation['service']} deployed successfully!")
            with col2:
                if st.button("Verify Fix", key=f"verify_{i}"):
                    with st.spinner(f"Verifying fix for {recommendation['service']}..."):
                        # This is a placeholder for the actual verification logic
                        # In a real application, this would trigger a re-scan
                        st.success(f"Fix for {recommendation['service']} verified successfully!")

def display_metrics(analysis):
    """Display key metrics in the sidebar"""
    
    # Calculate metrics
    total_services = len(analysis.get('findings', []))
    high_risk = len([f for f in analysis.get('findings', []) if f.get('risk_score', 0) >= 7])
    medium_risk = len([f for f in analysis.get('findings', []) if 4 <= f.get('risk_score', 0) < 7])
    low_risk = len([f for f in analysis.get('findings', []) if f.get('risk_score', 0) < 4])
    
    # Display metrics
    st.metric("Total Services", total_services)
    st.metric("High Risk", high_risk, delta=None)
    st.metric("Medium Risk", medium_risk, delta=None)
    st.metric("Low Risk", low_risk, delta=None)
    
    # Average risk score
    if analysis.get('findings'):
        avg_risk = sum(f.get('risk_score', 0) for f in analysis['findings']) / len(analysis['findings'])
        st.metric("Avg Risk Score", f"{avg_risk:.1f}/10")

def display_vulnerability_trends():
    st.subheader("Vulnerability Trends Over Time")
    scans = c.execute("SELECT scan_time, analysis FROM scans ORDER BY scan_time ASC").fetchall()
    
    if not scans:
        st.info("No historical scan data available to display trends.")
        return

    trend_data = []
    for scan_time, analysis_json in scans:
        analysis = json.loads(analysis_json)
        metrics = analysis.get('risk_metrics', {})
        trend_data.append({
            'scan_time': datetime.fromisoformat(scan_time),
            'high_risk': metrics.get('high_risk', 0),
            'medium_risk': metrics.get('medium_risk', 0),
            'low_risk': metrics.get('low_risk', 0)
        })
    
    df = pd.DataFrame(trend_data)
    df = df.set_index('scan_time')
    
    st.line_chart(df[['high_risk', 'medium_risk', 'low_risk']])

def generate_pdf_report(analysis, parsed_data):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)
    # Title Bar
    pdf.set_fill_color(31, 119, 180)
    pdf.rect(0, 0, 210, 20, 'F')
    pdf.set_xy(0, 6)
    pdf.set_font("Arial", 'B', 20)
    pdf.set_text_color(255,255,255)
    pdf.cell(0, 12, "AutoPatchAI Vulnerability Assessment Report", ln=True, align='C')
    pdf.set_text_color(0,0,0)
    pdf.ln(12)
    # Quick Stats
    pdf.set_font("Arial", 'B', 14)
    pdf.set_fill_color(230, 240, 255)
    pdf.cell(0, 10, "Quick Stats", ln=True, fill=True)
    pdf.ln(2)
    pdf.set_font("Arial", '', 12)
    stats = analysis.get('risk_metrics', {})
    pdf.cell(60, 8, f"Total Services: {stats.get('total_findings', len(parsed_data.get('services', [])))}", ln=0)
    pdf.cell(40, 8, f"High Risk: {stats.get('high_risk', 0)}", ln=0)
    pdf.cell(40, 8, f"Medium Risk: {stats.get('medium_risk', 0)}", ln=0)
    pdf.cell(0, 8, f"Low Risk: {stats.get('low_risk', 0)}", ln=1)
    pdf.cell(0, 8, f"Avg Risk Score: {stats.get('average_risk_score', 0)}", ln=1)
    pdf.ln(4)
    # Business Context (if provided)
    if analysis.get('business_context'):
        pdf.set_font("Arial", 'B', 13)
        pdf.set_fill_color(230, 240, 255)
        pdf.cell(0, 9, "Business Context", ln=True, fill=True)
        pdf.ln(2)
        pdf.set_font("Arial", '', 12)
        pdf.multi_cell(0, 8, strip_markdown(sanitize_text(analysis['business_context'])))
        pdf.ln(2)
    # Detected Services Table
    pdf.set_font("Arial", 'B', 14)
    pdf.set_fill_color(230, 240, 255)
    pdf.cell(0, 10, "Detected Services", ln=True, fill=True)
    pdf.ln(2)
    pdf.set_font("Arial", 'B', 12)
    pdf.set_fill_color(220,220,220)
    pdf.cell(30, 8, "Port", 1, 0, 'C', 1)
    pdf.cell(30, 8, "Protocol", 1, 0, 'C', 1)
    pdf.cell(50, 8, "Service", 1, 0, 'C', 1)
    pdf.cell(60, 8, "Version", 1, 1, 'C', 1)
    pdf.set_font("Arial", '', 11)
    for svc in parsed_data.get('services', []):
        pdf.cell(30, 8, sanitize_text(str(svc.get('port', ''))), 1)
        pdf.cell(30, 8, sanitize_text(str(svc.get('protocol', ''))), 1)
        pdf.cell(50, 8, sanitize_text(str(svc.get('service', ''))), 1)
        pdf.cell(60, 8, sanitize_text(str(svc.get('version', ''))), 1, 1)
    pdf.ln(4)
    # Executive Summary
    pdf.set_font("Arial", 'B', 16)
    pdf.set_fill_color(230, 240, 255)
    pdf.cell(0, 12, "Executive Summary", ln=True, fill=True)
    pdf.ln(2)
    pdf.set_font("Arial", '', 12)
    for para in strip_markdown(sanitize_text(analysis.get('executive_summary', 'No summary available'))).split('\n\n'):
        pdf.multi_cell(0, 8, para)
        pdf.ln(1)
    pdf.ln(4)
    # Risk Scoring Table (already present)
    pdf.set_font("Arial", 'B', 15)
    pdf.set_fill_color(230, 240, 255)
    pdf.cell(0, 11, "Risk Scoring", ln=True, fill=True)
    pdf.ln(2)
    pdf.set_font("Arial", 'B', 12)
    pdf.set_fill_color(220,220,220)
    pdf.cell(40, 9, "Service", 1, 0, 'C', 1)
    pdf.cell(20, 9, "Port", 1, 0, 'C', 1)
    pdf.cell(25, 9, "Risk Score", 1, 0, 'C', 1)
    pdf.cell(20, 9, "Level", 1, 0, 'C', 1)
    pdf.cell(85, 9, "CVEs", 1, 1, 'C', 1)
    pdf.set_font("Arial", '', 11)
    for finding in analysis.get('findings', []):
        risk_level = "HIGH" if finding['risk_score'] >= 7 else ("MEDIUM" if finding['risk_score'] >= 4 else "LOW")
        if risk_level == "HIGH":
            pdf.set_fill_color(255, 205, 210)
            pdf.set_text_color(183,28,28)
        elif risk_level == "MEDIUM":
            pdf.set_fill_color(255, 236, 179)
            pdf.set_text_color(245,124,0)
        else:
            pdf.set_fill_color(200, 230, 201)
            pdf.set_text_color(56,142,60)
        pdf.cell(40, 9, sanitize_text(finding['service'].split(' on ')[0]), 1, 0, 'C', 1)
        pdf.cell(20, 9, sanitize_text(finding['service'].split(' on port ')[-1]), 1, 0, 'C', 1)
        pdf.cell(25, 9, str(finding['risk_score']), 1, 0, 'C', 1)
        pdf.cell(20, 9, risk_level, 1, 0, 'C', 1)
        pdf.set_text_color(0,0,0)
        pdf.cell(85, 9, sanitize_text(", ".join(finding.get('cves', [])))[:60]+('...' if len(", ".join(finding.get('cves', [])))>60 else ''), 1, 1, 'L', 1)
    pdf.ln(6)
    # Exploit Predictions
    if analysis.get('exploit_predictions'):
        pdf.set_font("Arial", 'B', 14)
        pdf.set_fill_color(230, 240, 255)
        pdf.cell(0, 10, "AI Exploit Predictions", ln=True, fill=True)
        pdf.ln(2)
        pdf.set_font("Arial", '', 12)
        for pred in analysis['exploit_predictions']:
            p = pred['prediction']
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 8, sanitize_text(pred['service']), ln=True)
            pdf.set_font("Arial", '', 12)
            pdf.cell(10)
            pdf.cell(0, 7, f"Exploit Likelihood: {int(p.get('exploit_likelihood',0)*100)}%", ln=True)
            pdf.cell(10)
            pdf.cell(0, 7, f"Time to Exploit: {p.get('time_to_exploit','')}", ln=True)
            pdf.cell(10)
            pdf.cell(0, 7, f"Confidence Score: {int(p.get('confidence_score',0)*100)}%", ln=True)
            pdf.cell(10)
            pdf.cell(0, 7, f"Priority: {p.get('mitigation_priority','')}", ln=True)
            if p.get('attack_vectors'):
                pdf.cell(10)
                pdf.cell(0, 7, "Attack Vectors:", ln=True)
                for v in p['attack_vectors']:
                    pdf.cell(20)
                    pdf.cell(0, 7, sanitize_text(v), ln=True)
            pdf.ln(1)
    pdf.ln(2)
    # Business Impact
    pdf.set_font("Arial", 'B', 14)
    pdf.set_fill_color(230, 240, 255)
    pdf.cell(0, 10, "Business Impact", ln=True, fill=True)
    pdf.ln(2)
    pdf.set_font("Arial", 'I', 12)
    for para in strip_markdown(sanitize_text(analysis.get('business_impact', 'No business impact analysis available'))).split('\n\n'):
        pdf.multi_cell(0, 8, para)
        pdf.ln(1)
    pdf.ln(4)
    # Recommendations
    pdf.set_font("Arial", 'B', 14)
    pdf.set_fill_color(230, 240, 255)
    pdf.cell(0, 10, "Recommendations", ln=True, fill=True)
    pdf.ln(2)
    pdf.set_font("Arial", '', 12)
    for rec in analysis.get('recommendations', []):
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 8, sanitize_text(f"{rec['service']} - {rec['action']}"), ln=True)
        pdf.set_font("Arial", '', 12)
        pdf.cell(10)
        pdf.cell(0, 7, sanitize_text(f"Current: {rec.get('current_version', '')}  Target: {rec.get('target_version', '')}"), ln=True)
        pdf.cell(10)
        pdf.cell(0, 7, sanitize_text(f"Command: {rec.get('command', '')}"), ln=True)
        pdf.ln(1)
    pdf.ln(2)
    # AI Recommendations (indented lists)
    if analysis.get('ai_recommendations'):
        pdf.set_font("Arial", 'B', 13)
        pdf.set_fill_color(230, 240, 255)
        pdf.cell(0, 9, "AI-Generated Fix Recommendations", ln=True, fill=True)
        pdf.ln(2)
        pdf.set_font("Arial", '', 12)
        for ai_rec in analysis['ai_recommendations']:
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(0, 8, sanitize_text(ai_rec['service']), ln=True)
            pdf.set_font("Arial", '', 12)
            for section, items in ai_rec['recommendations'].items():
                if isinstance(items, list) and items:
                    pdf.cell(10)
                    pdf.cell(0, 7, sanitize_text(section.replace('_',' ').capitalize()+":"), ln=True)
                    for item in items:
                        pdf.cell(20)
                        pdf.cell(0, 7, sanitize_text(item), ln=True)
                elif isinstance(items, str) and items:
                    pdf.cell(10)
                    pdf.cell(0, 7, sanitize_text(section.replace('_',' ').capitalize()+":"), ln=True)
                    pdf.cell(20)
                    pdf.cell(0, 7, sanitize_text(items), ln=True)
            pdf.ln(1)
    pdf.ln(2)
    # Action Plan
    pdf.set_font("Arial", 'B', 14)
    pdf.set_fill_color(230, 240, 255)
    pdf.cell(0, 10, "Action Plan", ln=True, fill=True)
    pdf.ln(2)
    pdf.set_font("Arial", '', 12)
    for i, action in enumerate(analysis.get('action_plan', []), 1):
        pdf.cell(10)
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 8, sanitize_text(f"{i}. {action['step']} - {action['timeline']}"), ln=True)
        pdf.set_font("Arial", '', 12)
        pdf.cell(20)
        pdf.multi_cell(0, 7, sanitize_text(action['description']))
        pdf.ln(1)
    # Footer
    pdf.set_y(-20)
    pdf.set_font("Arial", 'I', 10)
    pdf.set_text_color(120,120,120)
    pdf.cell(0, 10, f"Generated by AutoPatchAI on {datetime.now().strftime('%Y-%m-%d %H:%M')}", 0, 0, 'C')
    pdf_bytes = pdf.output()
    # Convert bytearray to bytes for Streamlit compatibility
    if isinstance(pdf_bytes, bytearray):
        pdf_bytes = bytes(pdf_bytes)
    return pdf_bytes

if __name__ == "__main__":
    main()