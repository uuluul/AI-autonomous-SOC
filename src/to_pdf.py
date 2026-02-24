import os
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor

# --- 自定顏色配置 ---
COLOR_PRIMARY = HexColor("#1E88E5")
COLOR_SECONDARY = HexColor("#D32F2F")
COLOR_TABLE_HEADER = HexColor("#0D47A1")
COLOR_TABLE_TEXT = colors.whitesmoke
COLOR_ROW_EVEN = colors.white
COLOR_ROW_ODD = HexColor("#F5F5F5")

def generate_pdf_report(data: dict, output_path: str):
    """
    將 LLM 分析結果轉為 PDF 報告 (包含動態改善建議)
    """
    # 確保輸出目錄存在
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # 樣式定義
    title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontSize=24, spaceAfter=20, alignment=1, textColor=COLOR_PRIMARY)
    subtitle_style = ParagraphStyle('Subtitle', parent=styles['Normal'], fontSize=12, spaceAfter=20, alignment=1, textColor=colors.gray)
    h2_style = ParagraphStyle('Heading2', parent=styles['Heading2'], fontSize=16, spaceBefore=15, spaceAfter=10, textColor=COLOR_SECONDARY)
    normal_style = styles['Normal']
    
    # 標題區
    filename = data.get('filename', 'Unknown Report')
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    confidence = data.get('confidence', 0)
    
    story.append(Paragraph("CTI Threat Intelligence Report", title_style))
    story.append(Paragraph(f"Source: {filename} | Generated: {timestamp}", subtitle_style))
    story.append(Spacer(1, 0.2*inch))

    # 信心分數
    score_color = "green" if confidence > 80 else "orange" if confidence > 50 else "red"
    story.append(Paragraph(f"Threat Confidence Score: <font color='{score_color}'><b>{confidence}/100</b></font>", normal_style))
    story.append(Spacer(1, 0.2*inch))
    
    # 攻擊手法 (TTPs)
    story.append(Paragraph("Detected Attack Techniques (MITRE ATT&CK)", h2_style))
    ttps = data.get('ttps', [])
    if ttps:
        for ttp in ttps:
            # 嘗試抓取各種可能的欄位名稱
            t_id = ttp.get('mitre_technique_id') or ttp.get('id', 'N/A')
            t_name = ttp.get('name', 'Unknown')
            t_desc = ttp.get('description', '')[:200]
            text = f"<b>{t_id}</b> - {t_name}: {t_desc}..."
            story.append(Paragraph(f"• {text}", normal_style))
            story.append(Spacer(1, 0.05*inch))
    else:
        story.append(Paragraph("No specific TTPs detected.", normal_style))

    # 入侵指標 (IOCs) 表格
    story.append(Paragraph("Indicators of Compromise (IOCs)", h2_style))
    indicators = data.get('indicators', {})
    ioc_data = [["Type", "Value"]]
    
    for ip in indicators.get('ipv4', []) + indicators.get('ipv6', []): ioc_data.append(["IP Address", ip])
    for domain in indicators.get('domains', []): ioc_data.append(["Domain", domain])
    for url in indicators.get('urls', []): ioc_data.append(["URL", url[:60] + "..."])
    for alg, hash_list in indicators.get('hashes', {}).items():
        for h in hash_list: ioc_data.append([f"Hash ({alg})", h[:32] + "..."])

    if len(ioc_data) > 1:
        t = Table(ioc_data, colWidths=[2*inch, 4*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_TABLE_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), COLOR_TABLE_TEXT),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), COLOR_ROW_EVEN),
            ('ROWBACKGROUNDS', (1, 1), (-1, -1), [COLOR_ROW_ODD, COLOR_ROW_EVEN])
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No IOCs found in this report.", normal_style))

    # 防禦建議 (動態生成)
    story.append(Paragraph("Mitigation & Recommended Actions", h2_style))
    
    # 嘗試從 AI 分析結果中抓取 'courses_of_action' 或 'mitigation'
    mitigations = data.get('courses_of_action', [])
    if not mitigations:
        mitigations = data.get('mitigation', [])

    if mitigations:
        for idx, action in enumerate(mitigations, 1):
            if isinstance(action, dict):
                act_text = f"<b>{action.get('name', 'Action')}</b>: {action.get('description', '')}"
            else:
                act_text = str(action)
            story.append(Paragraph(f"{idx}. {act_text}", normal_style))
            story.append(Spacer(1, 0.05*inch))
    else:
        # 如果 AI 沒給建議，使用通用建議
        story.append(Paragraph("1. Block identified IOCs (IPs/Domains) in perimeter firewalls immediately.", normal_style))
        story.append(Paragraph("2. Review system logs (SIEM) for the mentioned TTPs pattern.", normal_style))
        story.append(Paragraph("3. Update Endpoint Detection (EDR) signatures.", normal_style))

    # 產出
    doc.build(story)
    print(f"  PDF Report generated: {output_path}")
    return output_path


# ─── Phase 5 Enhanced Report ─────────────────────────────────

COLOR_PHASE_PREDICT = HexColor("#FF9800")
COLOR_PHASE_DECEIVE = HexColor("#9C27B0")
COLOR_PHASE_MUTATE = HexColor("#2196F3")
COLOR_PHASE_CONTAIN = HexColor("#F44336")
COLOR_PHASE_ADAPT = HexColor("#4CAF50")


def generate_pdf_report_v2(data: dict, output_path: str):
    """
    Enhanced PDF report with full Phase 1-4 incident timeline.
    Called by Phase 5 AdaptEngine after incident lifecycle completes.

    data = {
        "filename": str,
        "confidence": int,
        "ttps": list,
        "indicators": dict,
        "courses_of_action": list,
        "timeline": dict,            # Phase 1-4 timeline
        "containment_actions": list,  # Firewall blocks
        "playbook_id": str,
    }
    """
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)

    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    # Styles
    title_style = ParagraphStyle('TitleV2', parent=styles['Heading1'], fontSize=22, spaceAfter=15, alignment=1, textColor=COLOR_PRIMARY)
    subtitle_style = ParagraphStyle('SubtitleV2', parent=styles['Normal'], fontSize=11, spaceAfter=15, alignment=1, textColor=colors.gray)
    h2_style = ParagraphStyle('H2V2', parent=styles['Heading2'], fontSize=15, spaceBefore=12, spaceAfter=8, textColor=COLOR_SECONDARY)
    h3_style = ParagraphStyle('H3V2', parent=styles['Heading3'], fontSize=12, spaceBefore=8, spaceAfter=6, textColor=COLOR_PRIMARY)
    normal_style = styles['Normal']

    # ─── Header ──────────────────────────────────────────
    filename = data.get('filename', 'Incident Report')
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    confidence = data.get('confidence', 0)

    story.append(Paragraph("NeoVigil Incident Response Report", title_style))
    story.append(Paragraph(f"{filename} | Generated: {timestamp}", subtitle_style))
    story.append(Spacer(1, 0.15 * inch))

    # Risk score
    score_color = "red" if confidence >= 80 else "orange" if confidence >= 50 else "green"
    story.append(Paragraph(
        f"Overall Risk Score: <font color='{score_color}'><b>{confidence}/100</b></font>",
        normal_style
    ))
    story.append(Spacer(1, 0.2 * inch))

    # ─── Phase Timeline ──────────────────────────────────
    timeline = data.get('timeline', {})
    phases = timeline.get('phases', {}) if isinstance(timeline, dict) else {}

    if phases:
        story.append(Paragraph("Incident Timeline (5-Phase Defense Lifecycle)", h2_style))

        phase_colors = {
            "predict": "#FF9800",
            "deceive": "#9C27B0",
            "mutate": "#2196F3",
            "contain": "#F44336",
            "adapt": "#4CAF50",
        }
        phase_labels = {
            "predict": "Phase 1: PREDICT",
            "deceive": "Phase 2: DECEIVE",
            "mutate": "Phase 3: MUTATE",
            "contain": "Phase 4: CONTAIN",
            "adapt": "Phase 5: ADAPT",
        }

        timeline_data = [["Phase", "Status", "Records"]]
        for phase_key in ["predict", "deceive", "mutate", "contain", "adapt"]:
            phase_data = phases.get(phase_key, {})
            if isinstance(phase_data, dict):
                count = phase_data.get("count", 0)
                status = "Active" if count > 0 else "N/A"
            else:
                count = 0
                status = "N/A"
            timeline_data.append([
                phase_labels.get(phase_key, phase_key.upper()),
                status,
                str(count),
            ])

        if len(timeline_data) > 1:
            t = Table(timeline_data, colWidths=[2.5 * inch, 1.5 * inch, 1.5 * inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), COLOR_TABLE_HEADER),
                ('TEXTCOLOR', (0, 0), (-1, 0), COLOR_TABLE_TEXT),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_ROW_ODD, COLOR_ROW_EVEN]),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.15 * inch))

    # ─── Containment Actions ─────────────────────────────
    containment = data.get('containment_actions', [])
    if containment:
        story.append(Paragraph("Containment Actions (Phase 4)", h2_style))

        block_data = [["IP Address", "Status", "Time (ms)"]]
        for block in containment[:20]:
            if isinstance(block, dict):
                block_data.append([
                    block.get("ip", "N/A"),
                    "Blocked" if block.get("success") else "Failed",
                    str(block.get("execution_time_ms", "N/A")),
                ])

        if len(block_data) > 1:
            t = Table(block_data, colWidths=[2.5 * inch, 1.5 * inch, 1.5 * inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor("#B71C1C")),
                ('TEXTCOLOR', (0, 0), (-1, 0), COLOR_TABLE_TEXT),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_ROW_ODD, COLOR_ROW_EVEN]),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.15 * inch))

    # ─── TTPs (reuse from v1) ────────────────────────────
    story.append(Paragraph("Detected Attack Techniques (MITRE ATT&CK)", h2_style))
    ttps = data.get('ttps', [])
    if ttps:
        for ttp in ttps[:10]:
            if isinstance(ttp, dict):
                t_id = ttp.get('technique_id') or ttp.get('mitre_technique_id') or ttp.get('id', 'N/A')
                t_name = ttp.get('name', ttp.get('tactic', 'Unknown'))
                text = f"<b>{t_id}</b> - {t_name}"
            else:
                text = str(ttp)
            story.append(Paragraph(f"  {text}", normal_style))
    else:
        story.append(Paragraph("No specific TTPs detected.", normal_style))

    # ─── IOCs ────────────────────────────────────────────
    story.append(Paragraph("Indicators of Compromise (IOCs)", h2_style))
    indicators = data.get('indicators', {})
    ioc_data = [["Type", "Value"]]
    for ip in indicators.get('ipv4', []) + indicators.get('ipv6', []):
        ioc_data.append(["IP Address", str(ip)])
    for domain in indicators.get('domains', []):
        ioc_data.append(["Domain", str(domain)])

    if len(ioc_data) > 1:
        t = Table(ioc_data, colWidths=[2 * inch, 4 * inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), COLOR_TABLE_HEADER),
            ('TEXTCOLOR', (0, 0), (-1, 0), COLOR_TABLE_TEXT),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [COLOR_ROW_ODD, COLOR_ROW_EVEN]),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No IOCs found.", normal_style))

    # ─── Recommended Actions ─────────────────────────────
    story.append(Paragraph("Mitigation & Recommended Actions", h2_style))
    mitigations = data.get('courses_of_action', []) or data.get('mitigation', [])
    if mitigations:
        for idx, action in enumerate(mitigations, 1):
            if isinstance(action, dict):
                act_text = f"<b>{action.get('name', 'Action')}</b>: {action.get('description', '')}"
            else:
                act_text = str(action)
            story.append(Paragraph(f"{idx}. {act_text}", normal_style))
    else:
        story.append(Paragraph("1. Block identified IOCs in perimeter firewalls.", normal_style))
        story.append(Paragraph("2. Review SIEM logs for detected TTP patterns.", normal_style))
        story.append(Paragraph("3. Update EDR signatures and rotate credentials.", normal_style))

    # ─── Playbook Reference ──────────────────────────────
    playbook_id = data.get('playbook_id')
    if playbook_id:
        story.append(Spacer(1, 0.15 * inch))
        story.append(Paragraph(
            f"SOAR Playbook: <b>{playbook_id}</b>", normal_style
        ))

    # Build
    doc.build(story)
    print(f"  Enhanced PDF Report generated: {output_path}")
    return output_path