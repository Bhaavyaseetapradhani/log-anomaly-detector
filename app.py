import streamlit as st
import anthropic
import json
import re
from datetime import datetime
from log_parser import parse_windows_logs, generate_sample_logs
from report_generator import generate_pdf_report

# ── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="LLM Log Anomaly Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
}

.stApp {
    background-color: #0a0e1a;
    color: #c9d1d9;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: #0d1117;
    border-right: 1px solid #1f2937;
}

/* Header */
.main-header {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2rem;
    color: #00ff88;
    text-shadow: 0 0 20px rgba(0,255,136,0.4);
    border-bottom: 1px solid #00ff8833;
    padding-bottom: 0.5rem;
    margin-bottom: 0.2rem;
}

.sub-header {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.85rem;
    color: #4a9eff;
    letter-spacing: 2px;
    margin-bottom: 1.5rem;
}

/* Severity badges */
.badge {
    display: inline-block;
    padding: 3px 12px;
    border-radius: 3px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem;
    font-weight: bold;
    letter-spacing: 1px;
}
.badge-critical { background: #ff000022; color: #ff4444; border: 1px solid #ff4444; }
.badge-high     { background: #ff6b0022; color: #ff6b00; border: 1px solid #ff6b00; }
.badge-medium   { background: #ffcc0022; color: #ffcc00; border: 1px solid #ffcc00; }
.badge-low      { background: #00ff8822; color: #00ff88; border: 1px solid #00ff88; }
.badge-info     { background: #4a9eff22; color: #4a9eff; border: 1px solid #4a9eff; }

/* Finding cards */
.finding-card {
    background: #0d1117;
    border: 1px solid #1f2937;
    border-left: 3px solid #00ff88;
    border-radius: 4px;
    padding: 1rem 1.2rem;
    margin: 0.6rem 0;
    font-family: 'Rajdhani', sans-serif;
}
.finding-card.critical { border-left-color: #ff4444; }
.finding-card.high     { border-left-color: #ff6b00; }
.finding-card.medium   { border-left-color: #ffcc00; }
.finding-card.low      { border-left-color: #00ff88; }

.finding-title {
    font-size: 1.05rem;
    font-weight: 700;
    color: #e6edf3;
    margin-bottom: 0.3rem;
}

.finding-explanation {
    font-size: 0.95rem;
    color: #8b949e;
    line-height: 1.5;
}

.finding-mitre {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: #4a9eff;
    margin-top: 0.4rem;
}

/* Metric cards */
.metric-row {
    display: flex;
    gap: 1rem;
    margin: 1rem 0;
}
.metric-card {
    flex: 1;
    background: #0d1117;
    border: 1px solid #1f2937;
    border-radius: 4px;
    padding: 1rem;
    text-align: center;
}
.metric-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2rem;
    font-weight: bold;
}
.metric-label {
    font-size: 0.8rem;
    color: #8b949e;
    letter-spacing: 1px;
    text-transform: uppercase;
}

/* Log box */
.log-box {
    background: #010409;
    border: 1px solid #1f2937;
    border-radius: 4px;
    padding: 1rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem;
    color: #7ee787;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
}

/* Buttons */
.stButton > button {
    background: #00ff8811 !important;
    color: #00ff88 !important;
    border: 1px solid #00ff88 !important;
    border-radius: 3px !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.85rem !important;
    letter-spacing: 1px !important;
    transition: all 0.2s !important;
}
.stButton > button:hover {
    background: #00ff8833 !important;
    box-shadow: 0 0 15px rgba(0,255,136,0.3) !important;
}

/* Text area */
.stTextArea textarea {
    background: #010409 !important;
    color: #7ee787 !important;
    border: 1px solid #1f2937 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.78rem !important;
}

/* Divider */
hr { border-color: #1f2937 !important; }

/* Spinner */
.stSpinner { color: #00ff88 !important; }

/* Selectbox, file uploader */
.stSelectbox > div > div, .stFileUploader > div {
    background: #0d1117 !important;
    border-color: #1f2937 !important;
    color: #c9d1d9 !important;
}

.scan-time {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: #4a9eff;
}
</style>
""", unsafe_allow_html=True)

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ Configuration")
    st.markdown("---")

    api_key = st.text_input(
        "Anthropic API Key",
        type="password",
        placeholder="sk-ant-...",
        help="Get yours at console.anthropic.com"
    )

    st.markdown("---")
    st.markdown("### 📋 About")
    st.markdown("""
    <div style='font-size:0.85rem; color:#8b949e; line-height:1.6'>
    Analyzes Windows Event Logs using Claude AI to detect anomalies, threats, and suspicious patterns.<br><br>
    Mirrors enterprise tools like <span style='color:#4a9eff'>Microsoft Copilot for Security</span>.
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("""
    <div style='font-family: Share Tech Mono, monospace; font-size:0.7rem; color:#4a9eff'>
    MITRE ATT&CK® MAPPED<br>
    SEVERITY SCORED<br>
    PDF REPORT EXPORT
    </div>
    """, unsafe_allow_html=True)

# ── Main Header ───────────────────────────────────────────────────────────────
st.markdown('<div class="main-header">⚡ LLM Log Anomaly Detector</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">WINDOWS EVENT LOG ANALYSIS · AI-POWERED · MITRE ATT&CK MAPPED</div>', unsafe_allow_html=True)

# ── Input section ─────────────────────────────────────────────────────────────
col1, col2 = st.columns([3, 1])

with col1:
    input_method = st.radio(
        "Input Method",
        ["📝 Paste logs", "📁 Upload .txt/.evtx", "🧪 Use sample logs"],
        horizontal=True
    )

with col2:
    st.markdown("<br>", unsafe_allow_html=True)

raw_logs = ""

if input_method == "📝 Paste logs":
    raw_logs = st.text_area(
        "Paste Windows Event Logs here",
        height=200,
        placeholder="Paste your Windows Event Log entries here...\nExample:\n[2024-01-15 03:22:11] EventID 4625 - An account failed to log on. Account: administrator Source: 192.168.1.105\n[2024-01-15 03:22:12] EventID 4625 - An account failed to log on..."
    )

elif input_method == "📁 Upload .txt/.evtx":
    uploaded_file = st.file_uploader("Upload log file", type=["txt", "log", "evtx"])
    if uploaded_file:
        try:
            raw_logs = uploaded_file.read().decode("utf-8", errors="ignore")
            st.success(f"✅ Loaded {len(raw_logs.splitlines())} lines from {uploaded_file.name}")
        except Exception as e:
            st.error(f"Error reading file: {e}")

elif input_method == "🧪 Use sample logs":
    scenario = st.selectbox(
        "Choose attack scenario",
        [
            "Brute Force + Lateral Movement",
            "Privilege Escalation via PowerShell",
            "Credential Dumping (Mimikatz)",
            "Ransomware Pre-deployment",
        ]
    )
    raw_logs = generate_sample_logs(scenario)
    st.markdown('<div class="log-box">' + raw_logs.replace('\n', '<br>') + '</div>', unsafe_allow_html=True)

st.markdown("---")

# ── Analyze button ────────────────────────────────────────────────────────────
analyze_clicked = st.button("🔍 ANALYZE LOGS", use_container_width=True)

if analyze_clicked:
    if not api_key:
        st.error("⚠️ Please enter your Anthropic API key in the sidebar.")
    elif not raw_logs.strip():
        st.error("⚠️ Please provide log data to analyze.")
    else:
        # Parse logs
        parsed = parse_windows_logs(raw_logs)

        with st.spinner("🤖 Claude is analyzing your logs..."):
            try:
                client = anthropic.Anthropic(api_key=api_key)

                prompt = f"""You are a senior SOC analyst. Analyze the following Windows Event Logs for security anomalies, threats, and suspicious patterns.

LOGS:
{raw_logs}

PARSED EVENTS SUMMARY:
{json.dumps(parsed, indent=2)}

Return ONLY a valid JSON object with this exact structure (no markdown, no explanation outside JSON):
{{
  "summary": "2-3 sentence executive summary of what you found",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "total_anomalies": <number>,
  "findings": [
    {{
      "id": 1,
      "title": "Short threat title",
      "severity": "Critical|High|Medium|Low",
      "event_ids": ["4625", "4624"],
      "explanation": "Plain English explanation of what happened and why it's suspicious",
      "mitre_technique": "T1078 - Valid Accounts",
      "mitre_tactic": "Initial Access",
      "recommendation": "Specific action to take"
    }}
  ],
  "timeline": "Brief attack timeline if applicable",
  "iocs": ["list", "of", "indicators", "of", "compromise"]
}}

Focus on: brute force, lateral movement, privilege escalation, persistence, credential access, unusual logon patterns, PowerShell abuse, suspicious processes."""

                response = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=2000,
                    messages=[{"role": "user", "content": prompt}]
                )

                raw_response = response.content[0].text.strip()

                # Clean JSON
                raw_response = re.sub(r'^```json\s*', '', raw_response)
                raw_response = re.sub(r'\s*```$', '', raw_response)

                analysis = json.loads(raw_response)

                # ── Store in session state ─────────────────────────────────
                st.session_state["analysis"] = analysis
                st.session_state["raw_logs"] = raw_logs
                st.session_state["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            except json.JSONDecodeError as e:
                st.error(f"Failed to parse AI response. Raw output:\n{raw_response}")
            except anthropic.AuthenticationError:
                st.error("❌ Invalid API key. Please check your Anthropic API key.")
            except Exception as e:
                st.error(f"Error: {str(e)}")

# ── Results ───────────────────────────────────────────────────────────────────
if "analysis" in st.session_state:
    analysis = st.session_state["analysis"]
    raw_logs = st.session_state["raw_logs"]
    scan_time = st.session_state.get("scan_time", "")

    st.markdown("---")
    st.markdown(f'<div class="scan-time">SCAN COMPLETED: {scan_time}</div>', unsafe_allow_html=True)
    st.markdown("<br>", unsafe_allow_html=True)

    # Risk level banner
    risk = analysis.get("risk_level", "UNKNOWN")
    risk_colors = {"CRITICAL": "#ff4444", "HIGH": "#ff6b00", "MEDIUM": "#ffcc00", "LOW": "#00ff88"}
    risk_color = risk_colors.get(risk, "#8b949e")

    st.markdown(f"""
    <div style='background:{risk_color}11; border:1px solid {risk_color}; border-radius:4px; padding:1rem 1.5rem; margin-bottom:1rem;'>
        <span style='font-family:Share Tech Mono,monospace; font-size:0.8rem; color:{risk_color}; letter-spacing:2px'>OVERALL RISK LEVEL</span><br>
        <span style='font-family:Share Tech Mono,monospace; font-size:2rem; color:{risk_color}; font-weight:bold'>{risk}</span>
    </div>
    """, unsafe_allow_html=True)

    # Summary
    st.markdown(f"""
    <div style='background:#0d1117; border:1px solid #1f2937; border-radius:4px; padding:1rem 1.5rem; margin-bottom:1rem; color:#c9d1d9; font-size:1rem; line-height:1.6'>
    {analysis.get('summary', '')}
    </div>
    """, unsafe_allow_html=True)

    # Metrics
    findings = analysis.get("findings", [])
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        if sev in sev_counts:
            sev_counts[sev] += 1

    cols = st.columns(5)
    metrics = [
        (str(analysis.get("total_anomalies", len(findings))), "ANOMALIES", "#4a9eff"),
        (str(sev_counts["Critical"]), "CRITICAL", "#ff4444"),
        (str(sev_counts["High"]), "HIGH", "#ff6b00"),
        (str(sev_counts["Medium"]), "MEDIUM", "#ffcc00"),
        (str(sev_counts["Low"]), "LOW", "#00ff88"),
    ]
    for col, (val, label, color) in zip(cols, metrics):
        col.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color:{color}">{val}</div>
            <div class="metric-label">{label}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Findings
    st.markdown("### 🔎 Findings")

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_findings = sorted(findings, key=lambda x: sev_order.get(x.get("severity", "Low"), 3))

    for finding in sorted_findings:
        sev = finding.get("severity", "Low").lower()
        sev_colors = {"critical": "#ff4444", "high": "#ff6b00", "medium": "#ffcc00", "low": "#00ff88"}
        color = sev_colors.get(sev, "#8b949e")

        event_ids_str = ", ".join([f"EventID {e}" for e in finding.get("event_ids", [])])

        st.markdown(f"""
        <div class="finding-card {sev}">
            <div style="display:flex; justify-content:space-between; align-items:flex-start">
                <div class="finding-title">#{finding.get('id','')} {finding.get('title','')}</div>
                <span class="badge badge-{sev}">{finding.get('severity','').upper()}</span>
            </div>
            <div style="font-family:Share Tech Mono,monospace; font-size:0.72rem; color:#4a9eff; margin:0.3rem 0">{event_ids_str}</div>
            <div class="finding-explanation">{finding.get('explanation','')}</div>
            <div class="finding-mitre">⚡ {finding.get('mitre_technique','')} · {finding.get('mitre_tactic','')}</div>
            <div style="margin-top:0.6rem; font-size:0.88rem; color:#c9d1d9">
                <span style="color:#00ff88; font-weight:700">→ REC:</span> {finding.get('recommendation','')}
            </div>
        </div>
        """, unsafe_allow_html=True)

    # IOCs
    iocs = analysis.get("iocs", [])
    if iocs:
        st.markdown("### 🎯 Indicators of Compromise")
        ioc_html = " ".join([f'<span style="background:#ff444411; border:1px solid #ff444444; padding:2px 10px; border-radius:3px; font-family:Share Tech Mono,monospace; font-size:0.78rem; color:#ff9999; margin:3px; display:inline-block">{i}</span>' for i in iocs])
        st.markdown(f'<div style="margin:0.5rem 0">{ioc_html}</div>', unsafe_allow_html=True)

    # Timeline
    timeline = analysis.get("timeline", "")
    if timeline:
        st.markdown("### ⏱️ Attack Timeline")
        st.markdown(f"""
        <div style='background:#0d1117; border:1px solid #1f2937; border-left:3px solid #4a9eff; border-radius:4px; padding:1rem 1.5rem; font-family:Share Tech Mono,monospace; font-size:0.82rem; color:#8b949e; line-height:1.8'>
        {timeline}
        </div>
        """, unsafe_allow_html=True)

    # PDF Export
    st.markdown("---")
    st.markdown("### 📄 Export Report")

    if st.button("⬇️ DOWNLOAD PDF REPORT", use_container_width=True):
        with st.spinner("Generating PDF report..."):
            try:
                pdf_bytes = generate_pdf_report(analysis, raw_logs, scan_time)
                st.download_button(
                    label="📥 Click to Download Report",
                    data=pdf_bytes,
                    file_name=f"soc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            except Exception as e:
                st.error(f"PDF generation failed: {e}")
