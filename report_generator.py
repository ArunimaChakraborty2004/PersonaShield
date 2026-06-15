import io
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import inch

# Brand colours
DARK_BG    = HexColor("#0f172a")
ACCENT     = HexColor("#3b82f6")
TEXT_DARK  = HexColor("#1e293b")
TEXT_MID   = HexColor("#334155")
TEXT_LIGHT = HexColor("#64748b")
BORDER     = HexColor("#cbd5e1")
RED        = HexColor("#ef4444")
GREEN      = HexColor("#10b981")
AMBER      = HexColor("#f59e0b")
PURPLE     = HexColor("#8b5cf6")


def _status_color(status, score=None):
    """Return a colour based on threat status / score."""
    s = (status or "").lower()
    if s == "malicious":
        return RED
    if s == "suspicious":
        return AMBER
    if s == "safe":
        return GREEN
    # Fallback to score
    if score is not None:
        if score >= 7:
            return RED
        if score >= 4:
            return AMBER
    return GREEN


def generate_pdf_report(scan_data, scan_type="message"):
    """
    Generates a professional PDF threat report.
    Returns a BytesIO object ready to be served as a download.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=0.6 * inch,
        leftMargin=0.6 * inch,
        topMargin=0.6 * inch,
        bottomMargin=0.6 * inch,
    )

    # ── Build fresh styles (never mutate the shared stylesheet) ──────
    base = getSampleStyleSheet()

    S = {}   # our private style map

    S["title"] = ParagraphStyle(
        "ps_title",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=22,
        textColor=white,
        spaceAfter=4,
        leading=26,
    )
    S["subtitle"] = ParagraphStyle(
        "ps_subtitle",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=11,
        textColor=HexColor("#93c5fd"),
        spaceAfter=0,
    )
    S["section"] = ParagraphStyle(
        "ps_section",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        textColor=ACCENT,
        spaceBefore=14,
        spaceAfter=6,
        leading=16,
    )
    S["label"] = ParagraphStyle(
        "ps_label",
        parent=base["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        textColor=TEXT_MID,
        spaceAfter=2,
    )
    S["value"] = ParagraphStyle(
        "ps_value",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=TEXT_DARK,
        spaceAfter=10,
        leading=14,
    )
    S["body"] = ParagraphStyle(
        "ps_body",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=TEXT_DARK,
        spaceAfter=8,
        leading=15,
    )
    S["bullet"] = ParagraphStyle(
        "ps_bullet",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=TEXT_DARK,
        spaceAfter=5,
        leading=14,
        leftIndent=12,
    )
    S["footer"] = ParagraphStyle(
        "ps_footer",
        parent=base["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8,
        textColor=TEXT_LIGHT,
        spaceBefore=20,
    )

    elements = []

    # ── Header Banner ─────────────────────────────────────────────────
    report_title = "URL Threat Analysis Report" if scan_type == "url" else "Message Threat Analysis Report"

    header_data = [[
        Paragraph(report_title, S["title"]),
        Paragraph("PersonaShield AI Security", S["subtitle"]),
    ]]
    header_table = Table(header_data, colWidths=[doc.width])
    header_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, -1), DARK_BG),
        ("TOPPADDING",   (0, 0), (-1, -1), 18),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 18),
        ("LEFTPADDING",  (0, 0), (-1, -1), 20),
        ("RIGHTPADDING", (0, 0), (-1, -1), 20),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("ROUNDEDCORNERS", [6]),
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 16))

    # ── Timestamp ─────────────────────────────────────────────────────
    timestamp = scan_data.get("timestamp", "Unknown")
    if hasattr(timestamp, "strftime"):
        timestamp_str = timestamp.strftime("%Y-%m-%d  %H:%M:%S  UTC")
    elif isinstance(timestamp, str):
        timestamp_str = timestamp.replace("T", "  ")[:19] + "  UTC"
    else:
        timestamp_str = str(timestamp)

    elements.append(Paragraph(f"<b>Report Generated:</b>  {timestamp_str}", S["body"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=10))

    # ── Determine key values ──────────────────────────────────────────
    if scan_type == "url":
        score   = scan_data.get("risk_score", 0)
        status  = scan_data.get("status", "Unknown")
        ttype   = scan_data.get("threat_type", "Unknown")
        content = scan_data.get("url", "—")
        content_label = "Target URL"
    else:
        score   = scan_data.get("score", 0)
        status  = scan_data.get("severity", "Unknown").capitalize()
        ttype   = scan_data.get("threat_type", "Unknown")
        content = scan_data.get("text", "—")
        content_label = "Message Content"

    confidence  = scan_data.get("confidence", 0)
    ai_powered  = scan_data.get("ai_powered", False)
    explanation = scan_data.get("explanation", "No explanation available.")
    recommendation = scan_data.get("recommendation", "No recommendation available.")
    score_color = _status_color(status, score)

    # ── Summary Table ─────────────────────────────────────────────────
    elements.append(Paragraph("Scan Summary", S["section"]))

    def cell(txt, bold=False, color=TEXT_DARK):
        style = ParagraphStyle("_c", parent=base["Normal"],
                               fontName="Helvetica-Bold" if bold else "Helvetica",
                               fontSize=10, textColor=color, leading=14)
        return Paragraph(txt, style)

    summary_rows = [
        [cell("Field", bold=True, color=white), cell("Value", bold=True, color=white)],
        [cell("Threat Type"),    cell(ttype)],
        [cell("Threat Score"),   cell(f"{score} / 10", bold=True, color=score_color)],
        [cell("Status"),         cell(status, bold=True, color=score_color)],
        [cell("Confidence"),     cell(f"{confidence}%")],
        [cell("AI Analysis"),    cell("Yes – AI Evaluated" if ai_powered else "No – Rule-based only")],
    ]

    col_w = doc.width / 2
    summary_table = Table(summary_rows, colWidths=[col_w, col_w])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  ACCENT),
        ("BACKGROUND",   (0, 1), (-1, -1), HexColor("#f8fafc")),
        ("ROWBACKGROUNDS",(0, 1),(-1, -1), [HexColor("#f8fafc"), HexColor("#f1f5f9")]),
        ("GRID",         (0, 0), (-1, -1), 0.5, BORDER),
        ("TOPPADDING",   (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 7),
        ("LEFTPADDING",  (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 12))

    # ── Content ───────────────────────────────────────────────────────
    elements.append(Paragraph(content_label, S["section"]))
    elements.append(Paragraph(str(content), S["body"]))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceAfter=8))

    # ── Analysis Details ──────────────────────────────────────────────
    elements.append(Paragraph("Analysis Details", S["section"]))
    elements.append(Paragraph(str(explanation), S["body"]))

    # ── Recommendation ────────────────────────────────────────────────
    elements.append(Paragraph("Recommendation", S["section"]))
    elements.append(Paragraph(str(recommendation), S["body"]))

    # ── Detection Sources (URL only) ──────────────────────────────────
    sources = scan_data.get("sources", [])
    if scan_type == "url" and sources:
        elements.append(Paragraph("Detection Sources", S["section"]))
        for src in sources:
            elements.append(Paragraph(f"•  {src}", S["bullet"]))

    # ── Footer ────────────────────────────────────────────────────────
    elements.append(HRFlowable(width="100%", thickness=0.5, color=BORDER, spaceBefore=16, spaceAfter=6))
    elements.append(Paragraph(
        "This report was automatically generated by PersonaShield AI Security. "
        "It is intended for informational purposes only.",
        S["footer"]
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer
