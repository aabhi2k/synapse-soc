"""
PDF Report Generator for SYNAPSE-SOC.
Generates an executive-grade, publication-ready PDF document documenting
the complete 7-Phase Live Streaming Architecture, Engineering Checklist,
Detection Rules, CADR Metrics, and Operator Runbook.
"""

import os
import sys
from pathlib import Path
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch


def create_pdf(output_filename: str = "SYNAPSE_SOC_Live_Architecture_Report.pdf"):
    pdf_path = Path(output_filename).resolve()
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    primary_color = colors.HexColor("#0f172a")    # Slate 900
    brand_blue = colors.HexColor("#1d4ed8")       # Blue 700
    accent_purple = colors.HexColor("#6d28d9")    # Purple 700
    text_dark = colors.HexColor("#1e293b")        # Slate 800
    text_muted = colors.HexColor("#64748b")       # Slate 500
    bg_light = colors.HexColor("#f8fafc")         # Slate 50
    success_green = colors.HexColor("#15803d")    # Green 700

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=primary_color,
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=brand_blue,
        spaceAfter=12
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=brand_blue,
        spaceBefore=10,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=primary_color,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=12,
        textColor=text_dark,
        spaceAfter=4
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10.5,
        textColor=colors.HexColor("#0f172a")
    )

    badge_done = Paragraph("<font color='#15803d'><b>[DONE]</b></font>", body_style)

    elements = []

    # HEADER BANNER
    elements.append(Paragraph("SYNAPSE-SOC: LIVE STREAMING SOC ARCHITECTURE", title_style))
    elements.append(Paragraph("7-Phase Engineering Verification & Operational Runbook | Microsoft Innovate 2026", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=brand_blue, spaceBefore=0, spaceAfter=8))

    # SECTION 1: EXECUTIVE OVERVIEW
    elements.append(Paragraph("1. Executive Summary & Architectural Transition", h1_style))
    overview_text = (
        "<b>SYNAPSE-SOC</b> has transitioned from an offline batch simulation tool into a <b>live event-driven, "
        "streaming SOC detection engine</b>. The platform continuously ingests telemetry across three live sources "
        "(Windows Security Event Logs, File Integrity Monitor with Watchdog, and SSH Deception Honeypot), normalizes them "
        "into a standardized <b>Common Alert Schema</b>, evaluates events against <b>5 stateful behavioral detection rules</b>, "
        "correlates multi-stage attacks over a <b>15-minute sliding window</b> using graph connected components, "
        "prioritizes incidents via <b>CADR Asset-Criticality metrics</b>, and renders real-time insights across a "
        "<b>Rich Live Terminal Console</b> and a <b>FastAPI Web Console</b> with interactive Telegram containment approval."
    )
    elements.append(Paragraph(overview_text, body_style))
    elements.append(Spacer(1, 4))

    # SECTION 2: 7-PHASE VERIFICATION CHECKLIST
    elements.append(Paragraph("2. 7-Phase Engineering & Deliverables Matrix", h1_style))
    
    table_data = [
        [
            Paragraph("<b>Phase & Focus Area</b>", h2_style),
            Paragraph("<b>Key Implementation Deliverables</b>", h2_style),
            Paragraph("<b>Core Source Files</b>", h2_style),
            Paragraph("<b>Status</b>", h2_style)
        ],
        [
            Paragraph("<b>Phase 1: Foundation</b><br/><font color='#64748b'>Common Schema & Queue</font>", body_style),
            Paragraph("Normalized schema (`source, type, host, user, src_ip, timestamp, severity`), `UnifiedEventQueue`, `BaseSource(ABC)`", body_style),
            Paragraph("`engine/models.py`<br/>`sources/base_source.py`<br/>`sources/event_queue.py`", code_style),
            badge_done
        ],
        [
            Paragraph("<b>Phase 2: Windows Event Log</b><br/><font color='#64748b'>Local OS Telemetry</font>", body_style),
            Paragraph("Event IDs 4625 (Failed), 4624 (Success), 4688 (Process Spawn), WinEvt XML/dict parser, Auditpol helper", body_style),
            Paragraph("`sources/windows_events.py`<br/>`sources/windows_auditing.py`", code_style),
            badge_done
        ],
        [
            Paragraph("<b>Phase 3: FIM Watchdog</b><br/><font color='#64748b'>Ransomware Detection</font>", body_style),
            Paragraph("Watchdog on `protected_assets/`, mass change (>20 files/10s), `.locked`/`.crypto` regex, test harness", body_style),
            Paragraph("`sources/fim_source.py`<br/>`test_fim_harness.py`", code_style),
            badge_done
        ],
        [
            Paragraph("<b>Phase 4: Streaming Brain</b><br/><font color='#64748b'>Stateful Sliding Correlator</font>", body_style),
            Paragraph("`on_new_alert(alert)` with 15-min sliding window, 5 core detection rules (T1110, T1078, T1059, T1486, T1046), CADR risk progression", body_style),
            Paragraph("`engine/streaming_correlator.py`<br/>`engine/detection_rules.py`<br/>`engine/risk_scorer.py`", code_style),
            badge_done
        ],
        [
            Paragraph("<b>Phase 5: Live Terminal UI</b><br/><font color='#64748b'>Rich Live Console</font>", body_style),
            Paragraph("Split-pane `rich.live.Live` console, top HUD bar (Events In, Incidents Out, Noise Compression %), explicit Tier Badges (T0-T3), 3-bullet AI brief", body_style),
            Paragraph("`live_dashboard.py`<br/>`engine/summarizer.py`", code_style),
            badge_done
        ],
        [
            Paragraph("<b>Phase 6: Notifications</b><br/><font color='#64748b'>Mobile Escalation & HITL</font>", body_style),
            Paragraph("Async Telegram/Discord bot, 10-min deduplication, grounded 3-bullet summary with cited Alert IDs, `[Block IP]` human confirmation", body_style),
            Paragraph("`notifications/telegram_bot.py`<br/>`notifications/notifier.py`", code_style),
            badge_done
        ],
        [
            Paragraph("<b>Phase 7: Honeypot & Polish</b><br/><font color='#64748b'>Deception, IP & Replay</font>", body_style),
            Paragraph("SSH deception honeypot (port 2222), Cowrie adapter, AbuseIPDB/GeoIP enrichment, `replay_mode.py`, 3-min end-to-end demo script", body_style),
            Paragraph("`sources/ssh_honeypot.py`<br/>`engine/ip_enrichment.py`<br/>`demo_attack_simulation.py`", code_style),
            badge_done
        ]
    ]

    t = Table(table_data, colWidths=[1.4*inch, 2.7*inch, 1.8*inch, 0.7*inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), bg_light),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 8))

    # SECTION 3: SPECIFIC UI FIX & CADR RISK SCORING
    elements.append(Paragraph("3. Left Panel UI Badge Fix & CADR Risk Model", h1_style))
    ui_fix_text = (
        "<b>Left Panel Asset Tier Badge Fix:</b> In the Web Console (`web/static/index.html`) and Terminal UI (`live_dashboard.py`), "
        "every incident row now clearly renders a color-coded asset tier badge:<br/>"
        "• <b>T0 (Crown Jewel):</b> Red/Purple badge with 3.0x CADR Multiplier (Domain Controllers, Key Identity Vaults).<br/>"
        "• <b>T1 (Mission Critical):</b> Amber badge with 2.0x CADR Multiplier (Core Databases, File Shares, Production APIs).<br/>"
        "• <b>T2 (Internal Business):</b> Blue badge with 1.0x Multiplier (Corporate Workstations, Internal Services).<br/>"
        "• <b>T3 (Dev / Lab / Honeypot):</b> Gray badge with 0.5x Multiplier (Isolated Sandboxes, Deception Traps).<br/>"
        "The sidebar filter dropdown and search bar seamlessly match by both badge codes (`T0`) and full names."
    )
    elements.append(Paragraph(ui_fix_text, body_style))
    elements.append(Spacer(1, 6))

    # SECTION 4: 5 CORE DETECTION RULES SPECIFICATION
    elements.append(Paragraph("4. 5 Core Stateful Detection Rules", h1_style))
    rules_table_data = [
        [
            Paragraph("<b>Rule Name & MITRE Tag</b>", h2_style),
            Paragraph("<b>Trigger Condition (15-min Sliding Window)</b>", h2_style),
            Paragraph("<b>Severity</b>", h2_style),
            Paragraph("<b>CADR Impact</b>", h2_style)
        ],
        [
            Paragraph("<b>1. Credential Brute Force</b><br/>T1110.001", body_style),
            Paragraph("&ge; 5 failed logon attempts (Event 4625) within 5 mins for same user/IP", body_style),
            Paragraph("HIGH", code_style),
            Paragraph("+25 pts (Access)", body_style)
        ],
        [
            Paragraph("<b>2. Post-Brute Valid Logon</b><br/>T1078 Valid Accounts", body_style),
            Paragraph("Successful logon (Event 4624) within 15 mins of &ge; 3 failed logon attempts", body_style),
            Paragraph("CRITICAL", code_style),
            Paragraph("+35 pts (Privilege)", body_style)
        ],
        [
            Paragraph("<b>3. Spawn After Logon</b><br/>T1059 Command Interpreter", body_style),
            Paragraph("PowerShell / CMD / Mimikatz spawned within 5 mins of interactive logon", body_style),
            Paragraph("CRITICAL", code_style),
            Paragraph("+25 pts (Execution)", body_style)
        ],
        [
            Paragraph("<b>4. Ransomware Velocity</b><br/>T1486 Data Encrypted", body_style),
            Paragraph("FIM Watchdog detects &gt; 20 file renames/mods in 10s or `.locked` extension", body_style),
            Paragraph("CRITICAL", code_style),
            Paragraph("+40 pts (Impact)", body_style)
        ],
        [
            Paragraph("<b>5. Honeypot Deception Probe</b><br/>T1046 Service Discovery", body_style),
            Paragraph("Direct inbound TCP/SSH connection attempt on isolated deception port 2222", body_style),
            Paragraph("HIGH", code_style),
            Paragraph("+20 pts (Recon)", body_style)
        ]
    ]
    t_rules = Table(rules_table_data, colWidths=[1.7*inch, 3.1*inch, 0.9*inch, 1.0*inch])
    t_rules.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), bg_light),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('PADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(t_rules)
    elements.append(Spacer(1, 6))

    # SECTION 5: OPERATOR RUNBOOK & DEMO SCRIPT
    elements.append(Paragraph("5. Operator Runbook & Verification Commands", h1_style))
    
    cmd_box = [
        [
            Paragraph("<b>Execution Goal</b>", h2_style),
            Paragraph("<b>Command Line (PowerShell / Command Prompt)</b>", h2_style)
        ],
        [
            Paragraph("<b>Interactive Launcher (All Modes)</b>", body_style),
            Paragraph("`.\\run_demo.bat`", code_style)
        ],
        [
            Paragraph("<b>3-Minute End-to-End Attack Demo</b>", body_style),
            Paragraph("`python demo_attack_simulation.py`  <i>(or `python main.py --demo`)</i>", code_style)
        ],
        [
            Paragraph("<b>Live Terminal Dashboard</b>", body_style),
            Paragraph("`python main.py --live`", code_style)
        ],
        [
            Paragraph("<b>Safe FIM Ransomware Harness</b>", body_style),
            Paragraph("`python test_fim_harness.py`", code_style)
        ],
        [
            Paragraph("<b>FastAPI Web SOC Console</b>", body_style),
            Paragraph("`python main.py --web`  <i>(Navigate to http://localhost:8000)</i>", code_style)
        ],
        [
            Paragraph("<b>Recorded Attack Replay Mode</b>", body_style),
            Paragraph("`python replay_mode.py --dataset data/captured_attacks.json --delay 0.5`", code_style)
        ],
        [
            Paragraph("<b>Automated Test Suite (15 Unit Tests)</b>", body_style),
            Paragraph("`python -m unittest discover -s tests`", code_style)
        ]
    ]
    t_cmd = Table(cmd_box, colWidths=[2.2*inch, 4.5*inch])
    t_cmd.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), bg_light),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('PADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(t_cmd)
    elements.append(Spacer(1, 6))

    # SECTION 6: SAFETY & TELEGRAM HITL APPROVAL
    elements.append(Paragraph("6. Safety Protocol & Human-in-the-Loop Response", h1_style))
    safety_text = (
        "• <b>Human-in-the-Loop Safety Gate:</b> All critical mitigation playbooks (such as <code>[Block IP]</code> "
        "and <code>[Isolate Host]</code>) strictly require manual analyst authorization before perimeter firewall ACL updates "
        "or EDR network isolation commands are dispatched.<br/>"
        "• <b>Safe Test Isolation:</b> The FIM simulation harness operates exclusively within isolated mock directories "
        "(`protected_assets/`) and performs automated cleanup.<br/>"
        "• <b>Credential Security:</b> Zero sensitive API tokens or secrets are hardcoded; all integrations rely on environment variables."
    )
    elements.append(Paragraph(safety_text, body_style))

    # Build document
    doc.build(elements)
    print(f"[+] Successfully generated PDF: {pdf_path}")
    return str(pdf_path)


if __name__ == "__main__":
    create_pdf()

