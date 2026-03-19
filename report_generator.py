"""
PDF Report Generator for SOC Log Analysis
Generates professional incident response reports
"""

import io
from datetime import datetime

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


def generate_pdf_report(analysis: dict, raw_logs: str, scan_time: str) -> bytes:
    """Generate a professional PDF SOC report."""

    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab is required. Run: pip install reportlab")

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm,
    )

    # ── Color palette ─────────────────────────────────────────────────────────
    C_BG        = colors.HexColor("#0a0e1a")
    C_GREEN     = colors.HexColor("#00ff88")
    C_BLUE      = colors.HexColor("#4a9eff")
    C_RED       = colors.HexColor("#ff4444")
    C_ORANGE    = colors.HexColor("#ff6b00")
    C_YELLOW    = colors.HexColor("#ffcc00")
    C_DARK      = colors.HexColor("#0d1117")
    C_BORDER    = colors.HexColor("#1f2937")
    C_TEXT      = colors.HexColor("#c9d1d9")
    C_MUTED     = colors.HexColor("#8b949e")

    severity_colors = {
        "Critical": C_RED,
        "High": C_ORANGE,
        "Medium": C_YELLOW,
        "Low": C_GREEN,
    }

    risk_colors = {
        "CRITICAL": C_RED,
        "HIGH": C_ORANGE,
        "MEDIUM": C_YELLOW,
        "LOW": C_GREEN,
    }

    # ── Styles ────────────────────────────────────────────────────────────────
    styles = getSampleStyleSheet()

    def style(name, **kwargs):
        return ParagraphStyle(name, **kwargs)

    title_style = style("Title",
        fontName="Helvetica-Bold", fontSize=20,
        textColor=C_GREEN, spaceAfter=4, leading=24)

    subtitle_style = style("Subtitle",
        fontName="Helvetica", fontSize=9,
        textColor=C_BLUE, spaceAfter=12, leading=12, letterSpacing=2)

    section_style = style("Section",
        fontName="Helvetica-Bold", fontSize=12,
        textColor=C_BLUE, spaceBefore=12, spaceAfter=6, leading=16)

    body_style = style("Body",
        fontName="Helvetica", fontSize=9,
        textColor=C_TEXT, leading=14, spaceAfter=6)

    mono_style = style("Mono",
        fontName="Courier", fontSize=7.5,
        textColor=C_GREEN, leading=11, spaceAfter=4)

    muted_style = style("Muted",
        fontName="Helvetica", fontSize=8,
        textColor=C_MUTED, leading=12)

    finding_title_style = style("FindingTitle",
        fontName="Helvetica-Bold", fontSize=10,
        textColor=C_TEXT, leading=14)

    finding_body_style = style("FindingBody",
        fontName="Helvetica", fontSize=8.5,
        textColor=C_MUTED, leading=13)

    mitre_style = style("MITRE",
        fontName="Courier", fontSize=8,
        textColor=C_BLUE, leading=12)

    rec_style = style("Rec",
        fontName="Helvetica-Oblique", fontSize=8.5,
        textColor=C_TEXT, leading=12)

    # ── Build content ─────────────────────────────────────────────────────────
    elements = []
    W = A4[0] - 40*mm  # usable width

    def hr(color=C_BORDER, thickness=0.5):
        return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=8, spaceBefore=4)

    # Header block
    elements.append(Paragraph("⚡ LLM LOG ANOMALY DETECTOR", title_style))
    elements.append(Paragraph("WINDOWS SECURITY INCIDENT REPORT", subtitle_style))
    elements.append(hr(C_GREEN, 1))

    # Meta table
    risk = analysis.get("risk_level", "UNKNOWN")
    meta_data = [
        ["SCAN DATE", scan_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["OVERALL RISK", risk],
        ["TOTAL ANOMALIES", str(analysis.get("total_anomalies", len(analysis.get("findings", []))))],
        ["REPORT GENERATED", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
    ]

    risk_color = risk_colors.get(risk, C_MUTED)

    meta_table = Table(meta_data, colWidths=[40*mm, W - 40*mm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_DARK),
        ("TEXTCOLOR", (0, 0), (0, -1), C_MUTED),
        ("TEXTCOLOR", (1, 0), (1, -1), C_TEXT),
        ("TEXTCOLOR", (1, 1), (1, 1), risk_color),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 1), (1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [C_DARK, colors.HexColor("#0f1621")]),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 10))

    # Executive Summary
    elements.append(Paragraph("EXECUTIVE SUMMARY", section_style))
    elements.append(hr())
    elements.append(Paragraph(analysis.get("summary", "No summary available."), body_style))
    elements.append(Spacer(1, 8))

    # Severity breakdown
    findings = analysis.get("findings", [])
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        sev = f.get("severity", "Low")
        if sev in sev_counts:
            sev_counts[sev] += 1

    sev_data = [["CRITICAL", "HIGH", "MEDIUM", "LOW"]]
    sev_data.append([
        str(sev_counts["Critical"]),
        str(sev_counts["High"]),
        str(sev_counts["Medium"]),
        str(sev_counts["Low"]),
    ])

    sev_table = Table(sev_data, colWidths=[W/4]*4)
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C_DARK),
        ("TEXTCOLOR", (0, 0), (0, 0), C_RED),
        ("TEXTCOLOR", (1, 0), (1, 0), C_ORANGE),
        ("TEXTCOLOR", (2, 0), (2, 0), C_YELLOW),
        ("TEXTCOLOR", (3, 0), (3, 0), C_GREEN),
        ("TEXTCOLOR", (0, 1), (0, 1), C_RED),
        ("TEXTCOLOR", (1, 1), (1, 1), C_ORANGE),
        ("TEXTCOLOR", (2, 1), (2, 1), C_YELLOW),
        ("TEXTCOLOR", (3, 1), (3, 1), C_GREEN),
        ("FONTNAME", (0, 0), (-1, 0), "Courier-Bold"),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7.5),
        ("FONTSIZE", (0, 1), (-1, 1), 20),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.3, C_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    elements.append(sev_table)
    elements.append(Spacer(1, 12))

    # Timeline
    timeline = analysis.get("timeline", "")
    if timeline:
        elements.append(Paragraph("ATTACK TIMELINE", section_style))
        elements.append(hr())
        elements.append(Paragraph(timeline, mono_style))
        elements.append(Spacer(1, 8))

    # Findings
    elements.append(Paragraph("DETAILED FINDINGS", section_style))
    elements.append(hr())

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    sorted_findings = sorted(findings, key=lambda x: sev_order.get(x.get("severity", "Low"), 3))

    for finding in sorted_findings:
        sev = finding.get("severity", "Low")
        sev_color = severity_colors.get(sev, C_MUTED)
        event_ids = ", ".join([f"EventID {e}" for e in finding.get("event_ids", [])])

        finding_data = [
            [
                Paragraph(f"#{finding.get('id','')} {finding.get('title','')}", finding_title_style),
                Paragraph(sev.upper(), style(f"sev_{sev}",
                    fontName="Helvetica-Bold", fontSize=8,
                    textColor=sev_color, alignment=TA_RIGHT)),
            ],
            [Paragraph(event_ids, mitre_style), ""],
            [Paragraph(finding.get("explanation", ""), finding_body_style), ""],
            [Paragraph(f"⚡ {finding.get('mitre_technique','')} · {finding.get('mitre_tactic','')}", mitre_style), ""],
            [Paragraph(f"→ {finding.get('recommendation','')}", rec_style), ""],
        ]

        ft = Table(finding_data, colWidths=[W - 30*mm, 30*mm])
        ft.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), C_DARK),
            ("LEFTBORDERPADDING", (0, 0), (-1, -1), 0),
            ("GRID", (0, 0), (-1, -1), 0, colors.white),
            ("LINEAFTER", (0, 0), (-1, -1), 0, colors.white),
            ("LINEBEFORE", (0, 0), (0, -1), 2, sev_color),
            ("BOX", (0, 0), (-1, -1), 0.3, C_BORDER),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("SPAN", (0, 1), (1, 1)),
            ("SPAN", (0, 2), (1, 2)),
            ("SPAN", (0, 3), (1, 3)),
            ("SPAN", (0, 4), (1, 4)),
        ]))
        elements.append(ft)
        elements.append(Spacer(1, 6))

    # IOCs
    iocs = analysis.get("iocs", [])
    if iocs:
        elements.append(Spacer(1, 4))
        elements.append(Paragraph("INDICATORS OF COMPROMISE", section_style))
        elements.append(hr())
        for ioc in iocs:
            elements.append(Paragraph(f"• {ioc}", mono_style))

    # Raw log snippet
    elements.append(Spacer(1, 8))
    elements.append(Paragraph("RAW LOG SAMPLE (first 30 lines)", section_style))
    elements.append(hr())
    log_lines = raw_logs.strip().splitlines()[:30]
    log_snippet = "\n".join(log_lines)
    elements.append(Paragraph(log_snippet.replace("\n", "<br/>"), mono_style))

    # Footer note
    elements.append(Spacer(1, 16))
    elements.append(hr(C_BORDER))
    elements.append(Paragraph(
        "Generated by LLM Log Anomaly Detector · Powered by Claude AI · MITRE ATT&CK® Framework",
        style("Footer", fontName="Helvetica", fontSize=7, textColor=C_MUTED, alignment=TA_CENTER)
    ))

    # Build PDF
    doc.build(elements)
    buffer.seek(0)
    return buffer.read()
