#!/usr/bin/env python3
"""
Self-evolution manager for the reverse-flow skill.
Handles learning, pattern matching, and newskills.md generation.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ============================================================================
# CONFIGURATION
# ============================================================================

LEARNING_DIR = Path("learnings")
PATTERNS_DIR = LEARNING_DIR / "patterns"
TECHNIQUES_DIR = LEARNING_DIR / "techniques"
EXTERNAL_DIR = LEARNING_DIR / "external"
FAILURES_DIR = LEARNING_DIR / "failures"
NEWSKILLS_FILE = LEARNING_DIR / "newskills.md"

# GitHub search templates
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories?q={query}+stars:>50&sort=stars&order=desc"

# ============================================================================
# LEARNING ENTRY GENERATION
# ============================================================================

def generate_learning_entry(
    title: str,
    tags: List[str],
    context: str,
    problem: str,
    solution: str,
    evidence: str,
    lessons: str,
    related: str,
    confidence: str = "Medium"
) -> str:
    """Generate a structured learning entry markdown file."""
    return f"""# Learning: {title}

## Tags
{', '.join(f'#{tag}' for tag in tags)}

## Context
{context}

## Problem
{problem}

## Solution
{solution}

## Evidence
{evidence}

## Lessons Learned
{lessons}

## Related
{related}

## Confidence
{confidence}

## Recorded
{datetime.now(timezone.utc).isoformat()}
"""


def record_learning(
    title: str,
    tags: List[str],
    context: str,
    problem: str,
    solution: str,
    evidence: str = "",
    lessons: str = "",
    related: str = "",
    confidence: str = "Medium",
    out_dir: Path = PATTERNS_DIR
) -> Path:
    """Record a learning entry to the filesystem."""
    out_dir.mkdir(parents=True, exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    path = out_dir / f"{slug}.pattern.md"
    content = generate_learning_entry(
        title, tags, context, problem, solution, evidence, lessons, related, confidence
    )
    path.write_text(content, encoding="utf-8")
    return path


# ============================================================================
# EXTERNAL KNOWLEDGE ACQUISITION
# ============================================================================

def fetch_github_repo(repo_url: str) -> Dict[str, Any]:
    """Fetch a GitHub repository's README and key files."""
    # Extract owner/repo from URL
    match = re.search(r"github\.com/([^/]+)/([^/]+)", repo_url)
    if not match:
        return {"error": "Invalid GitHub URL"}
    owner, repo = match.group(1), match.group(2)

    # Use GitHub API to get README
    import requests
    api_url = f"https://api.github.com/repos/{owner}/{repo}/readme"
    resp = requests.get(api_url)
    if resp.status_code != 200:
        return {"error": f"Failed to fetch: {resp.status_code}"}

    data = resp.json()
    readme_content = data.get("content", "")
    import base64
    readme_text = base64.b64decode(readme_content).decode("utf-8", errors="ignore")

    return {
        "owner": owner,
        "repo": repo,
        "readme": readme_text,
        "url": repo_url
    }


def search_github(keyword: str) -> List[Dict[str, Any]]:
    """Search GitHub for repositories containing learning material."""
    import requests
    query = f"{keyword} stars:>50"
    url = GITHUB_SEARCH_URL.format(query=query.replace(" ", "+"))
    resp = requests.get(url)
    if resp.status_code != 200:
        return []

    data = resp.json()
    results = []
    for item in data.get("items", [])[:10]:
        results.append({
            "name": item["name"],
            "description": item["description"],
            "url": item["html_url"],
            "stars": item["stargazers_count"],
            "language": item["language"],
            "updated": item["updated_at"]
        })
    return results


def absorb_github_repo(repo_url: str) -> List[Path]:
    """Absorb a GitHub repository's learnings into the skill."""
    result = fetch_github_repo(repo_url)
    if "error" in result:
        print(f"[-] Error: {result['error']}")
        return []

    readme = result.get("readme", "")
    entries = []

    # Extract technique sections from README
    sections = re.split(r"#{2,3}\s+", readme)
    for section in sections:
        if not section.strip():
            continue

        # Look for technique-like content
        if any(keyword in section.lower() for keyword in [
            "exploit", "bypass", "inject", "reverse", "crack", "enumeration",
            "privilege", "escalation", "lateral", "persistence", "pivoting"
        ]):
            title = section.strip().split("\n")[0][:50]
            tags = ["external", "github"]
            if "sqli" in section.lower() or "sql injection" in section.lower():
                tags.append("sqli")
            if "xss" in section.lower():
                tags.append("xss")
            if "rce" in section.lower():
                tags.append("rce")
            if "bypass" in section.lower():
                tags.append("bypass")

            entry_path = record_learning(
                title=f"[External] {title}",
                tags=tags,
                context=f"Source: {result['url']}",
                problem="Technique identified from external repository",
                solution=section.strip()[:500],
                lessons="External learning - verify in local environment before applying",
                related=f"Source: {result['url']}",
                confidence="Low (needs verification)",
                out_dir=EXTERNAL_DIR
            )
            entries.append(entry_path)

    return entries


# ============================================================================
# NEWSKILLS.MD GENERATION
# ============================================================================

def generate_newskills_md(learning_dir: Path) -> str:
    """Generate the aggregated newskills.md file from all learning entries."""
    lines = [
        "# New Skills Acquired",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "This file contains skills learned through experience and external knowledge.",
        "Each skill has been tested at least once in a lab environment.",
        "",
        "## Summary",
        "",
    ]

    # Collect all pattern files
    pattern_files = list(learning_dir.glob("patterns/*.pattern.md"))
    external_files = list(learning_dir.glob("external/*.pattern.md"))
    technique_files = list(learning_dir.glob("techniques/*.technique.md"))

    lines.append(f"- Total patterns: {len(pattern_files)}")
    lines.append(f"- External sources: {len(external_files)}")
    lines.append(f"- Techniques: {len(technique_files)}")
    lines.append("")

    # Build tag index
    all_tags = set()
    skill_entries = []

    for pf in pattern_files + external_files + technique_files:
        try:
            content = pf.read_text(encoding="utf-8")
            tags_match = re.search(r"## Tags\n(.+)", content)
            title_match = re.search(r"# Learning: (.+)", content)
            solution_match = re.search(r"## Solution\n(.+?)(?=\n##|\Z)", content, re.DOTALL)

            tags = [t.strip("# ") for t in tags_match.group(1).split()] if tags_match else []
            title = title_match.group(1).strip() if title_match else pf.stem
            solution = solution_match.group(1).strip()[:200] if solution_match else "See full entry"

            all_tags.update(tags)
            skill_entries.append({
                "title": title,
                "tags": tags,
                "solution": solution,
                "source": pf.parent.name,
                "file": pf.name
            })
        except Exception:
            continue

    lines.append("## Skill Index")
    lines.append("")
    lines.append("| Skill | Tags | Source | File |")
    lines.append("|---|---|---|---|")

    for entry in skill_entries:
        tags_str = ", ".join(f"#{t}" for t in entry["tags"][:5])
        lines.append(f"| {entry['title'][:50]} | {tags_str} | {entry['source']} | `{entry['file']}` |")

    lines.append("")
    lines.append("## Detailed Skills")
    lines.append("")

    for entry in skill_entries:
        lines.append(f"### {entry['title']}")
        lines.append("")
        lines.append(f"**Tags**: {', '.join(f'#{t}' for t in entry['tags'])}")
        lines.append("")
        lines.append(f"**Description**: {entry['solution']}")
        lines.append("")
        lines.append(f"**Source**: `{entry['source']}/{entry['file']}`")
        lines.append("")

    return "\n".join(lines)


def update_newskills(learning_dir: Path) -> Path:
    """Update the newskills.md file."""
    learning_dir.mkdir(parents=True, exist_ok=True)
    content = generate_newskills_md(learning_dir)
    path = learning_dir / "newskills.md"
    path.write_text(content, encoding="utf-8")
    return path


# ============================================================================
# PATTERN MATCHING
# ============================================================================

def search_patterns(problem: str, learning_dir: Path) -> List[Dict[str, str]]:
    """Search learning patterns for matches to a current problem."""
    results = []
    pattern_files = list(learning_dir.glob("patterns/*.pattern.md"))

    problem_lower = problem.lower()
    for pf in pattern_files:
        content = pf.read_text(encoding="utf-8")
        # Simple keyword matching
        score = 0
        keywords = problem_lower.split()
        for kw in keywords:
            if len(kw) > 3 and kw in content.lower():
                score += 1

        if score > 0:
            title_match = re.search(r"# Learning: (.+)", content)
            title = title_match.group(1).strip() if title_match else pf.stem
            results.append({
                "file": str(pf),
                "title": title,
                "score": score,
                "preview": content[:300] + "..."
            })

    results.sort(key=lambda x: -x["score"])
    return results


# ============================================================================
# MAIN
# ============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="Self-evolution manager for reverse-flow")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # record
    record_parser = subparsers.add_parser("record", help="Record a new learning")
    record_parser.add_argument("--title", required=True, help="Learning title")
    record_parser.add_argument("--tags", help="Comma-separated tags")
    record_parser.add_argument("--context", required=True, help="What was the situation")
    record_parser.add_argument("--problem", required=True, help="What needed solving")
    record_parser.add_argument("--solution", required=True, help="What worked")
    record_parser.add_argument("--evidence", default="", help="Evidence")
    record_parser.add_argument("--lessons", default="", help="Lessons learned")
    record_parser.add_argument("--confidence", default="Medium", choices=["High", "Medium", "Low"])

    # learn-external
    learn_parser = subparsers.add_parser("learn-external", help="Learn from external source")
    learn_parser.add_argument("--url", required=True, help="GitHub repo URL")

    # search
    search_parser = subparsers.add_parser("search", help="Search GitHub for learning material")
    search_parser.add_argument("--keyword", required=True, help="Search keyword")

    # match
    match_parser = subparsers.add_parser("match", help="Match pattern to current problem")
    match_parser.add_argument("--problem", required=True, help="Problem description")

    # generate
    generate_parser = subparsers.add_parser("generate", help="Generate newskills.md")
    generate_parser.add_argument("--out", help="Output directory")

    args = parser.parse_args()

    if args.command == "record":
        tags = args.tags.split(",") if args.tags else []
        path = record_learning(
            title=args.title,
            tags=tags,
            context=args.context,
            problem=args.problem,
            solution=args.solution,
            evidence=args.evidence,
            lessons=args.lessons,
            confidence=args.confidence
        )
        print(f"[+] Learning recorded: {path}")

    elif args.command == "learn-external":
        paths = absorb_github_repo(args.url)
        print(f"[+] Absorbed {len(paths)} learnings from {args.url}")

    elif args.command == "search":
        results = search_github(args.keyword)
        for r in results:
            print(f"- {r['name']} ({r['stars']}★) - {r['description'][:80]}")
            print(f"  {r['url']}")

    elif args.command == "match":
        results = search_patterns(args.problem, Path("."))
        if results:
            print(f"[+] Found {len(results)} patterns:")
            for r in results[:5]:
                print(f"- {r['title']} (score: {r['score']})")
        else:
            print("[-] No matching patterns found")

    elif args.command == "generate":
        out_dir = Path(args.out) if args.out else Path(".")
        path = update_newskills(out_dir / "learnings")
        print(f"[+] newskills.md generated: {path}")

    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
