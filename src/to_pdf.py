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