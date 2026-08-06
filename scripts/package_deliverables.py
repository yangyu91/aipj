#!/usr/bin/env python3
"""
Package all findings into a deliverable archive with HTML report.
Triggered by "结束测试" command.
"""
from __future__ import annotations

import argparse
import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>漏洞报告 - {target}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
        .summary {{ background: #16213e; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .vuln-card {{ background: #16213e; border-left: 4px solid #e94560; padding: 15px; margin: 15px 0; border-radius: 4px; }}
        .vuln-card.critical {{ border-left-color: #ff0000; }}
        .vuln-card.high {{ border-left-color: #ff6600; }}
        .vuln-card.medium {{ border-left-color: #ffcc00; }}
        .vuln-card.low {{ border-left-color: #00ccff; }}
        .evidence {{ background: #0f0f1f; padding: 10px; border-radius: 4px; overflow-x: auto; font-family: monospace; white-space: pre-wrap; }}
        pre {{ background: #0f0f1f; padding: 10px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; }}
        .nav {{ display: flex; gap: 10px; flex-wrap: wrap; }}
        .nav a {{ color: #00ccff; text-decoration: none; background: #16213e; padding: 8px 16px; border-radius: 4px; }}
        .nav a:hover {{ background: #1a2a5e; }}
        .metadata {{ color: #aaa; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #16213e; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 1px solid #333; color: #666; text-align: center; }}
    </style>
</head>
<body>
<div class="container">
    <h1>🔍 漏洞报告: {target}</h1>
    <p class="metadata">生成时间: {timestamp} | 目标: {target} | 测试环境: {environment}</p>

    <div class="summary">
        <h2>执行摘要</h2>
        <p>{executive_summary}</p>
        <ul>
            <li>总漏洞数: {total_vulns}</li>
            <li>严重: {critical_count}</li>
            <li>高危: {high_count}</li>
            <li>中危: {medium_count}</li>
            <li>低危: {low_count}</li>
        </ul>
    </div>

    <h2 id="ddos">DDoS 压力测试结果</h2>
    [DDOS_TABLE]

    <div class="nav">
        <a href="#vuln-list">漏洞列表</a>
        <a href="#ddos">DDoS 测试</a>
        <a href="#lessons">经验教训</a>
        <a href="#remediation">修复建议</a>
    </div>

    <h2 id="vuln-list">漏洞详情</h2>
    {vulnerability_cards}

    <h2 id="lessons">经验教训</h2>
    {lessons_learned}

    <h2 id="remediation">修复建议</h2>
    {remediation_summary}

    <div class="footer">
        🛡️ 本报告由 Reverse Flow 自动生成 | 仅供授权测试使用
    </div>
</div>
</body>
</html>
'''

VULN_CARD_TEMPLATE = '''
<div class="vuln-card {severity_class}">
    <h3>{vuln_id}: {vuln_title}</h3>
    <p><strong>严重程度:</strong> {severity}</p>
    <p><strong>受影响组件:</strong> {component}</p>
    <p><strong>描述:</strong> {description}</p>
    <h4>复现步骤</h4>
    <pre>{reproduction_steps}</pre>
    <h4>Payload</h4>
    <pre>{payload}</pre>
    <h4>请求/响应</h4>
    <div class="evidence">{request_response}</div>
    <h4>证据文件</h4>
    <ul>
        {evidence_files}
    </ul>
    <h4>修复建议</h4>
    <pre>{remediation}</pre>
</div>
'''


# ============================================================================
# DELIVERABLE PACKAGING
# ============================================================================

def create_package(
    case_dir: Path,
    target: str,
    environment: str = "local sandbox",
    executive_summary: str = "",
    vulnerabilities: List[Dict[str, Any]] = None,
    lessons: str = "",
    remediation: str = "",
    ddos_results: List[Dict[str, Any]] = None,
    output_dir: Path = None
) -> Path:
    """Create a deliverable package with HTML report and per-vuln directories."""
    if vulnerabilities is None:
        vulnerabilities = []
    if ddos_results is None:
        ddos_results = []

    output_dir = output_dir or Path("deliverables")
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    archive_name = f"deliverables_{timestamp}"
    archive_path = output_dir / f"{archive_name}.zip"

    # Create temporary staging directory
    staging = output_dir / archive_name
    staging.mkdir(parents=True, exist_ok=True)

    # Copy newskills.md if exists
    newskills_path = case_dir / "learnings" / "newskills.md"
    if newskills_path.exists():
        shutil.copy(newskills_path, staging / "newskills.md")

    # Create per-vulnerability directories and copy evidence
    vuln_cards = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for vuln in vulnerabilities:
        vuln_id = vuln.get("id", f"VULN-{len(vuln_cards)+1:03d}")
        vuln_dir = staging / vuln_id
        vuln_dir.mkdir(parents=True, exist_ok=True)

        # Create subdirectories
        (vuln_dir / "reproduce").mkdir(exist_ok=True)
        (vuln_dir / "evidence").mkdir(exist_ok=True)
        (vuln_dir / "documentation").mkdir(exist_ok=True)

        # Save reproduce steps
        if vuln.get("reproduce_script"):
            (vuln_dir / "reproduce" / "exploit.py").write_text(
                vuln["reproduce_script"], encoding="utf-8"
            )
        if vuln.get("reproduce_steps"):
            (vuln_dir / "reproduce" / "steps.txt").write_text(
                vuln["reproduce_steps"], encoding="utf-8"
            )

        # Save evidence files
        evidence_files_html = ""
        if vuln.get("evidence_files"):
            for ef in vuln["evidence_files"]:
                src = Path(ef)
                if src.exists():
                    dst = vuln_dir / "evidence" / src.name
                    shutil.copy(src, dst)
                    evidence_files_html += f'<li><a href="./{vuln_id}/evidence/{src.name}">{src.name}</a></li>\n'

        if vuln.get("evidence_screenshot"):
            src = Path(vuln["evidence_screenshot"])
            if src.exists():
                dst = vuln_dir / "evidence" / src.name
                shutil.copy(src, dst)
                evidence_files_html += f'<li><a href="./{vuln_id}/evidence/{src.name}">截图</a></li>\n'

        # Save documentation
        if vuln.get("documentation"):
            (vuln_dir / "documentation" / "technical.md").write_text(
                vuln["documentation"], encoding="utf-8"
            )

        # Count severity
        severity = vuln.get("severity", "medium").lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
        else:
            severity_counts["medium"] += 1

        # Build vulnerability card
        vuln_cards.append(VULN_CARD_TEMPLATE.format(
            severity_class=severity,
            severity=severity.upper(),
            vuln_id=vuln_id,
            vuln_title=vuln.get("title", "Untitled Vulnerability"),
            component=vuln.get("component", "Unknown"),
            description=vuln.get("description", "No description provided"),
            reproduction_steps=vuln.get("reproduce_steps", "Not documented"),
            payload=vuln.get("payload", "No payload documented"),
            request_response=vuln.get("request_response", "No request/response captured"),
            evidence_files=evidence_files_html or "<li>无证据文件</li>",
            remediation=vuln.get("remediation", "No remediation provided")
        ))

    # Build DDoS test results table
    ddos_html = ""
    if ddos_results:
        ddos_html = "<table><tr><th>测试 #</th><th>攻击类型</th><th>速率</th><th>持续时间</th><th>延迟</th><th>错误率</th></tr>"
        for test in ddos_results:
            ddos_html += f"<tr><td>{test.get('id', '')}</td><td>{test.get('type', '')}</td><td>{test.get('rate', '')}</td><td>{test.get('duration', '')}</td><td>{test.get('latency', '')}</td><td>{test.get('error_rate', '')}</td></tr>"
        ddos_html += "</table>"
    else:
        ddos_html = "<p>本次测试未包含 DDoS 压力测试。</p>"

    # Generate HTML report
    html_content = HTML_TEMPLATE.format(
        target=target,
        timestamp=datetime.now(timezone.utc).isoformat(),
        environment=environment,
        executive_summary=executive_summary or f"对 {target} 进行渗透测试，共发现 {len(vulnerabilities)} 个漏洞。",
        total_vulns=len(vulnerabilities),
        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
        medium_count=severity_counts["medium"],
        low_count=severity_counts["low"],
        vulnerability_cards="\n".join(vuln_cards),
        lessons_learned=lessons or "本次测试未记录新的经验教训。",
        remediation_summary=remediation or "本次测试未提供整体修复建议。"
    )
    html_content = html_content.replace("[DDOS_TABLE]", ddos_html)

    (staging / "index.html").write_text(html_content, encoding="utf-8")

    # Create zip archive
    with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file in staging.rglob("*"):
            if file.is_file():
                zf.write(file, file.relative_to(staging))

    # Clean up staging
    shutil.rmtree(staging)

    return archive_path


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="Package deliverables from penetration test")
    parser.add_argument("--case-dir", required=True, help="Case directory path")
    parser.add_argument("--target", required=True, help="Target URL or description")
    parser.add_argument("--environment", default="local sandbox", help="Test environment")
    parser.add_argument("--executive-summary", default="", help="Executive summary text")
    parser.add_argument("--lessons", default="", help="Lessons learned")
    parser.add_argument("--remediation", default="", help="Remediation summary")
    parser.add_argument("--vulns", help="JSON file containing vulnerability data")
    parser.add_argument("--out", help="Output directory for deliverables")
    args = parser.parse_args()

    vulnerabilities = []
    if args.vulns:
        vulns_path = Path(args.vulns)
        if vulns_path.exists():
            vulnerabilities = json.loads(vulns_path.read_text(encoding="utf-8"))

    archive_path = create_package(
        case_dir=Path(args.case_dir),
        target=args.target,
        environment=args.environment,
        executive_summary=args.executive_summary,
        vulnerabilities=vulnerabilities,
        lessons=args.lessons,
        remediation=args.remediation,
        output_dir=Path(args.out) if args.out else None
    )

    print(f"[+] Deliverables packaged: {archive_path}")
    print(f"[+] Size: {archive_path.stat().st_size / 1024:.1f} KB")
    print(f"[+] Unpack and open index.html in browser.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
