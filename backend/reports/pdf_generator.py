
from datetime import datetime
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether,
)


def generate_pdf_report(scan: dict[str, Any]) -> bytes:
    """Generate a PDF security assessment report and return PDF bytes."""

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=17 * mm,
        leftMargin=17 * mm,
        topMargin=17 * mm,
        bottomMargin=17 * mm,
        title="SecureScope AI Security Assessment Report",
        author="SecureScope AI",
    )

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            alignment=TA_CENTER,
            textColor=colors.HexColor("#243b6b"),
            spaceAfter=8,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            textColor=colors.HexColor("#243b6b"),
            spaceBefore=12,
            spaceAfter=6,
        )
    )

    styles.add(
        ParagraphStyle(
            name="SmallBody",
            parent=styles["BodyText"],
            fontSize=8.5,
            leading=11,
            wordWrap="CJK",
        )
    )

    def safe(value: Any) -> str:
        """Escape values before placing them in PDF paragraphs."""
        text = str(value if value is not None else "Not provided")
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )

    findings = scan.get("findings", [])

    if not isinstance(findings, list):
        findings = []

    valid_findings = [
        finding for finding in findings
        if isinstance(finding, dict)
    ]

    levels = [
        str(finding.get("risk_level", "INFO")).upper()
        for finding in valid_findings
    ]

    story = [
        Paragraph("SecureScope AI", styles["ReportTitle"]),
        Paragraph(
            "Security Assessment Report",
            styles["Heading2"],
        ),
        Spacer(1, 4 * mm),
    ]

    metadata = [
        ["Target", safe(scan.get("target", "Not provided"))],
        ["Scan ID", safe(scan.get("id", "Not provided"))],
        [
            "Generated at",
            datetime.now().astimezone().strftime(
                "%Y-%m-%d %H:%M:%S %Z"
            ),
        ],
        [
            "Recorded at",
            safe(scan.get("created_at", "Not provided")),
        ],
    ]

    metadata_table = Table(
        metadata,
        colWidths=[38 * mm, 130 * mm],
    )

    metadata_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (0, -1),
                colors.HexColor("#edf2fa"),
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (0, -1),
                colors.HexColor("#243b6b"),
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#cbd5e1"),
            ),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("RIGHTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )

    story.extend([
        metadata_table,
        Paragraph("Executive Summary", styles["SectionHeading"]),
        Paragraph(
            "This report summarizes findings returned by SecureScope AI. "
            "Risk levels and remediation advice are rule-based guidance. "
            "An open port or detected service alone does not confirm "
            "a vulnerability.",
            styles["BodyText"],
        ),
        Paragraph("Risk Summary", styles["SectionHeading"]),
    ])

    summary_rows = [
        ["Metric", "Count"],
        ["Total findings", str(len(valid_findings))],
        [
            "High / Critical",
            str(sum(
                level in ("HIGH", "CRITICAL")
                for level in levels
            )),
        ],
        ["Medium", str(levels.count("MEDIUM"))],
        ["Low", str(levels.count("LOW"))],
        [
            "Informational",
            str(sum(
                level in ("INFO", "INFORMATIONAL")
                for level in levels
            )),
        ],
    ]

    summary_table = Table(
        summary_rows,
        colWidths=[100 * mm, 35 * mm],
        repeatRows=1,
    )

    summary_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#243b6b"),
            ),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#cbd5e1"),
            ),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [colors.white, colors.HexColor("#f5f7fb")],
            ),
            ("ALIGN", (1, 0), (1, -1), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 7),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ])
    )

    story.extend([
        summary_table,
        Paragraph(
            "Findings and Recommendations",
            styles["SectionHeading"],
        ),
    ])

    if not valid_findings:
        story.append(
            Paragraph(
                "No findings were returned for this assessment.",
                styles["BodyText"],
            )
        )

    for index, finding in enumerate(valid_findings, start=1):
        heading = (
            f"{index}. {safe(finding.get('service', 'Unknown service'))} "
            f"(Port {safe(finding.get('port', 'Unknown'))})"
        )

        detail_rows = [
            [
                "Risk level",
                safe(finding.get("risk_level", "INFO")),
            ],
            [
                "Priority",
                safe(finding.get("priority", "Not assigned")),
            ],
            [
                "Risk score",
                safe(finding.get("risk_score", "Not assigned")),
            ],
            [
                "Encrypted",
                safe(finding.get("encrypted", "Unknown")),
            ],
            [
                "Explanation",
                Paragraph(
                    safe(finding.get(
                        "explanation",
                        "No explanation provided.",
                    )),
                    styles["SmallBody"],
                ),
            ],
            [
                "Remediation",
                Paragraph(
                    safe(finding.get(
                        "remediation",
                        "No remediation guidance provided.",
                    )),
                    styles["SmallBody"],
                ),
            ],
        ]

        details_table = Table(
            detail_rows,
            colWidths=[35 * mm, 133 * mm],
        )

        details_table.setStyle(
            TableStyle([
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#edf2fa"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#243b6b"),
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.4,
                    colors.HexColor("#cbd5e1"),
                ),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ])
        )

        story.append(
            KeepTogether([
                Paragraph(heading, styles["Heading3"]),
                details_table,
                Spacer(1, 4 * mm),
            ])
        )

    story.extend([
        Spacer(1, 5 * mm),
        Paragraph(
            "Disclaimer: Review findings in the context of the system "
            "and your authorization. This report is an assessment aid, "
            "not proof of exploitability or a substitute for a full "
            "security audit.",
            styles["SmallBody"],
        ),
    ])

    document.build(story)

    return buffer.getvalue()
