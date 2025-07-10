# 🔒 AutoPatchAI - Intelligent Vulnerability Assessment & Patch Management

AutoPatchAI is a comprehensive cybersecurity tool that analyzes Nmap scan results to identify vulnerabilities, assess risks, and provide actionable patch recommendations. It combines automated parsing, AI-powered analysis, and executive-friendly reporting.

## 🚀 Features

### Core Capabilities
- **Multi-format Support**: Parse Nmap results in XML or plain text format
- **AI-Powered Analysis**: Advanced vulnerability assessment with dynamic risk scoring
- **AI-Generated Fix Recommendations**: Detailed remediation steps with configuration changes
- **Exploit Prediction**: AI-driven likelihood assessment and attack vector identification
- **Enhanced Executive Summaries**: Business-focused reporting with financial impact analysis
- **Comprehensive Reporting**: Technical findings, risk scoring, and executive summaries
- **Patch Recommendations**: Specific version updates and vendor advisories
- **Business Impact Analysis**: Executive-friendly risk assessment and action plans

### Risk Assessment
- **Dynamic Risk Scoring (1-10)**: Based on CVSS scores, exploit availability, and business impact
- **AI Exploit Prediction**: Machine learning-based likelihood assessment with confidence scores
- **Attack Vector Identification**: AI-driven analysis of potential attack methods
- **CVE Database**: Integrated vulnerability database with known exploits
- **Business Context**: Considers environment type, compliance requirements, and asset criticality
- **Threat Intelligence**: Incorporates exploit availability and recent vulnerability trends

### User Interface
- **Streamlit Web App**: Modern, responsive web interface
- **Real-time Analysis**: Instant vulnerability assessment and recommendations
- **Interactive Reports**: Expandable sections for detailed findings
- **Export Capabilities**: JSON and CSV export options

## 📋 Requirements

- Python 3.8+
- Streamlit
- Required packages (see `requirements.txt`)

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd AutoPatchAI
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure OpenAI API (Optional but Recommended)**:
   ```bash
   python setup_api.py
   ```
   Or set your API key as an environment variable:
   ```bash
   export OPENAI_API_KEY="your-openai-api-key-here"
   ```

4. **Run the application**:
   ```bash
   streamlit run app.py
   ```

5. **Access the web interface**:
   Open your browser and navigate to `http://localhost:8501`

## 📊 Usage

### Input Methods

1. **Upload Nmap XML**: Upload an Nmap scan result in XML format
2. **Paste Nmap Output**: Paste plain text Nmap results directly
3. **Use Sample Data**: Test with the included sample scan

### Analysis Settings

- **Include CVSS Scores**: Enable/disable CVSS score inclusion
- **Include Exploit Availability**: Show exploit availability information
- **Business Context**: Add organizational context for better risk assessment

### Output Sections

1. **AI-Enhanced Executive Summary**: Business-focused analysis with financial impact
2. **Technical Findings**: Detected services and versions
3. **Risk Scoring**: Dynamic risk scores with vulnerability details
4. **AI Exploit Predictions**: Likelihood assessment and attack vectors
5. **AI-Generated Fix Recommendations**: Detailed remediation with configuration changes
6. **Traditional Patch Recommendations**: Specific update commands and vendor advisories
7. **Business Impact Summary**: Executive-friendly risk analysis
8. **Action Plan**: Prioritized remediation steps

## 🔍 Example Analysis

### Sample Input
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
```

### Sample Output

**Risk Assessment**:
- OpenSSH 7.2p2: Risk Score 8/10 (High)
- Apache 2.4.18: Risk Score 9/10 (Critical)

**AI Exploit Predictions**:
- OpenSSH: 70% exploit likelihood, 1-2 weeks to exploit
- Apache: 80% exploit likelihood, 24-48 hours to exploit

**AI-Generated Fix Recommendations**:
- **Immediate Actions**: Disable root login, enable key-based auth, update versions
- **Configuration Changes**: Set MaxAuthTries, configure session management
- **Security Measures**: Implement fail2ban, WAF, rate limiting
- **Monitoring**: Track failed logins, monitor access patterns

**Key Vulnerabilities**:
- CVE-2016-10009: Privilege escalation (CVSS 7.5)
- CVE-2017-3167: Remote code execution (CVSS 9.8)

**Patch Recommendations**:
- Update OpenSSH to 8.9p1 or later
- Update Apache to 2.4.57 or later
- Implement security headers and WAF

## 🏗️ Project Structure

```
AutoPatchAI/
├── app.py           # Streamlit web application
├── parser.py        # Nmap parsing and data extraction
├── ai_module.py     # AI-powered vulnerability analysis
├── requirements.txt # Python dependencies
├── sample_scan.xml  # Sample Nmap XML for testing
└── README.md       # This file
```

## 🔧 Technical Details

### Parser Module (`parser.py`)
- Supports XML and plain text Nmap output
- Extracts service information, versions, and port details
- Handles multiple service types and version formats
- Export capabilities (JSON, CSV)

### AI Module (`ai_module.py`)
- Vulnerability database with CVE information
- Dynamic risk scoring algorithm
- Business impact assessment
- Patch recommendation generation
- Executive summary generation

### Web Application (`app.py`)
- Streamlit-based user interface
- Real-time analysis and reporting
- Interactive data visualization
- Export and sharing capabilities

## 🎯 Risk Scoring Algorithm

The dynamic risk score (1-10) is calculated using:

- **CVSS Score (40%)**: Base vulnerability severity
- **Exploit Availability (30%)**: Public exploit availability
- **Business Impact (20%)**: Environment and compliance factors
- **Service Criticality (10%)**: Service importance and exposure

## 📈 Business Impact Analysis

The tool provides:

- **Financial Impact Estimates**: Based on vulnerability type and business context
- **Downtime Projections**: Estimated service disruption times
- **Compliance Risk Assessment**: PCI DSS, HIPAA, SOX considerations
- **Actionable Recommendations**: Prioritized remediation steps

## 🔒 Security Considerations

- **Local Processing**: All analysis performed locally
- **No Data Transmission**: Scan results stay on your system
- **Vulnerability Database**: Local database with known CVEs
- **Audit Trail**: Timestamped analysis results

## 🚀 Future Enhancements

- **Real-time CVE Updates**: Integration with NVD API
- **Advanced Exploit Intelligence**: Integration with exploit databases
- **Automated Patching**: Integration with configuration management tools
- **Compliance Reporting**: Automated compliance assessment reports
- **Threat Modeling**: Advanced attack path analysis

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for educational and security assessment purposes. Always ensure you have proper authorization before scanning systems. The authors are not responsible for any misuse of this software.

---

**AutoPatchAI** - Making vulnerability assessment accessible and actionable for both technical teams and executives. 