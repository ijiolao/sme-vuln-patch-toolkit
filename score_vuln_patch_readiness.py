#!/usr/bin/env python3
"""
score_vuln_patch_readiness.py

Reads a CSV of vulnerability & patch readiness responses (0–3 per question),
calculates an overall maturity score, domain scores, and writes a Markdown report.

Expected input CSV format:

    question_id,score
    1,2
    2,3
    3,1
    ...
    54,2

Scoring:
    0 = Not implemented
    1 = Partially implemented
    2 = Mostly implemented
    3 = Fully implemented
"""

import argparse
import csv
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


# ---- Configuration: questionnaire domains & scoring model --------------------


# Mapping of domain names to the question IDs they cover.
# Based on Vulnerability Management Questionnaire structure:
#  1–7: Governance & Policy
#  8–13: Asset Inventory & Classification
# 14–19: Vulnerability Scanning & Tools
# 20–26: Patch Management Process
# 27–32: Configuration & Baseline Security
# 33–37: Endpoint & Server Patch Coverage
# 38–41: Cloud & SaaS Security
# 42–45: Vulnerability Triage & Prioritisation
# 46–49: Reporting & Metrics
# 50–54: Continuous Improvement
DOMAIN_QUESTIONS: Dict[str, List[int]] = {
    "Governance & Policy": list(range(1, 8)),
    "Asset Inventory & Classification": list(range(8, 14)),
    "Vulnerability Scanning & Tools": list(range(14, 20)),
    "Patch Management Process": list(range(20, 27)),
    "Configuration & Baseline Security": list(range(27, 33)),
    "Endpoint & Server Patch Coverage": list(range(33, 38)),
    "Cloud & SaaS Security": list(range(38, 42)),
    "Vulnerability Triage & Prioritisation": list(range(42, 46)),
    "Reporting & Metrics": list(range(46, 50)),
    "Continuous Improvement": list(range(50, 55)),
}

MAX_SCORE_PER_QUESTION = 3
TOTAL_QUESTIONS = 54
MAX_TOTAL_SCORE = TOTAL_QUESTIONS * MAX_SCORE_PER_QUESTION  # 162


@dataclass
class DomainScore:
    name: str
    score: int
    max_score: int
    percentage: float


@dataclass
class OverallScore:
    total_score: int
    max_score: int
    percentage: float
    maturity_level: str


# ---- Scoring functions ------------------------------------------------------


def load_responses(path: Path) -> Dict[int, int]:
    """
    Load responses from a CSV file.

    Expected columns: question_id, score
    - question_id: 1–54
    - score: integer 0–3
    """
    responses: Dict[int, int] = {}

    with path.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        expected_cols = {"question_id", "score"}
        if not expected_cols.issubset({c.strip() for c in reader.fieldnames or []}):
            raise ValueError(
                f"Input file {path} must contain columns: question_id, score "
                f"(found: {reader.fieldnames})"
            )

        for row in reader:
            try:
                qid = int(row["question_id"])
            except (TypeError, ValueError):
                raise ValueError(f"Invalid question_id value: {row.get('question_id')}")

            try:
                score = int(row["score"])
            except (TypeError, ValueError):
                raise ValueError(f"Invalid score for question {qid}: {row.get('score')}")

            if not (1 <= qid <= TOTAL_QUESTIONS):
                raise ValueError(f"question_id {qid} is outside expected range 1–{TOTAL_QUESTIONS}")
            if score not in (0, 1, 2, 3):
                raise ValueError(
                    f"Invalid score {score} for question {qid}. Expected 0, 1, 2, or 3."
                )

            responses[qid] = score

    # Optional: warn if some questions are missing
    missing = sorted(set(range(1, TOTAL_QUESTIONS + 1)) - set(responses.keys()))
    if missing:
        sys.stderr.write(
            f"Warning: responses missing for {len(missing)} questions: {missing}\n"
        )

    return responses


def calculate_overall_score(responses: Dict[int, int]) -> OverallScore:
    total_score = sum(responses.get(qid, 0) for qid in range(1, TOTAL_QUESTIONS + 1))
    percentage = (total_score / MAX_TOTAL_SCORE * 100) if MAX_TOTAL_SCORE else 0.0
    maturity = classify_maturity(total_score)
    return OverallScore(
        total_score=total_score,
        max_score=MAX_TOTAL_SCORE,
        percentage=percentage,
        maturity_level=maturity,
    )


def classify_maturity(total_score: int) -> str:
    """
    Map raw score to a maturity band.

    Based on the ranges defined in the questionnaire:

        0–40   = Very Low Maturity
        41–80  = Low Maturity
        81–120 = Moderate Maturity
        121–162 = High Maturity
    """
    if total_score <= 40:
        return "Very Low Maturity"
    if total_score <= 80:
        return "Low Maturity"
    if total_score <= 120:
        return "Moderate Maturity"
    return "High Maturity"


def calculate_domain_scores(responses: Dict[int, int]) -> List[DomainScore]:
    domain_scores: List[DomainScore] = []

    for domain, qids in DOMAIN_QUESTIONS.items():
        score = sum(responses.get(qid, 0) for qid in qids)
        max_score = len(qids) * MAX_SCORE_PER_QUESTION
        pct = (score / max_score * 100) if max_score else 0.0
        domain_scores.append(
            DomainScore(name=domain, score=score, max_score=max_score, percentage=pct)
        )

    return domain_scores


def find_weak_questions(
    responses: Dict[int, int],
    threshold: int = 1,
) -> List[int]:
    """
    Return a list of question IDs where the score is <= threshold.
    By default, returns questions scored 0 or 1.
    """
    return [qid for qid, score in responses.items() if score <= threshold]


# ---- Report generation ------------------------------------------------------


def generate_markdown_report(
    responses: Dict[int, int],
    overall: OverallScore,
    domains: List[DomainScore],
    input_path: Path,
) -> str:
    from datetime import datetime

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Sort domains for strengths/weaknesses
    sorted_domains = sorted(domains, key=lambda d: d.percentage, reverse=True)
    top_strengths = sorted_domains[:3]
    top_gaps = sorted_domains[-3:]

    weak_questions = find_weak_questions(responses, threshold=1)

    lines: List[str] = []

    lines.append("# Vulnerability & Patch Readiness Assessment Report")
    lines.append("")
    lines.append(f"- **Generated:** {timestamp}")
    lines.append(f"- **Source file:** `{input_path.name}`")
    lines.append("")
    lines.append("## 1. Overall Readiness Score")
    lines.append("")
    lines.append(f"- **Total Score:** {overall.total_score} / {overall.max_score}")
    lines.append(f"- **Overall Readiness:** {overall.percentage:.1f}%")
    lines.append(f"- **Maturity Level:** **{overall.maturity_level}**")
    lines.append("")
    lines.append("> Scoring model: 0 = Not implemented, 1 = Partially, 2 = Mostly, 3 = Fully implemented.")
    lines.append("")

    # Domain table
    lines.append("## 2. Domain Scores")
    lines.append("")
    lines.append("| Domain | Score | Max | % |")
    lines.append("|--------|-------|-----|---|")
    for d in domains:
        lines.append(
            f"| {d.name} | {d.score} | {d.max_score} | {d.percentage:.1f}% |"
        )
    lines.append("")

    # Strengths & improvement areas
    lines.append("## 3. Strengths & Improvement Areas")
    lines.append("")
    lines.append("### 3.1 Key Strengths (Top Domains)")
    lines.append("")
    if top_strengths:
        for d in top_strengths:
            lines.append(f"- **{d.name}** – {d.percentage:.1f}% ({d.score}/{d.max_score})")
    else:
        lines.append("- No data available.")
    lines.append("")
    lines.append("### 3.2 Priority Improvement Areas (Lowest Domains)")
    lines.append("")
    if top_gaps:
        for d in top_gaps:
            lines.append(f"- **{d.name}** – {d.percentage:.1f}% ({d.score}/{d.max_score})")
    else:
        lines.append("- No data available.")
    lines.append("")

    # Weak questions
    lines.append("## 4. Weak Controls (Questions Scored 0–1)")
    lines.append("")
    if weak_questions:
        lines.append(
            "The following question IDs scored **0 or 1**. "
            "These represent weak or partially implemented practices:"
        )
        lines.append("")
        # Group in lines of 10
        chunk_size = 10
        for i in range(0, len(weak_questions), chunk_size):
            chunk = weak_questions[i : i + chunk_size]
            lines.append("- " + ", ".join(str(q) for q in chunk))
    else:
        lines.append("All answered questions scored 2 or higher.")
    lines.append("")

    lines.append("## 5. Recommended Next Steps")
    lines.append("")
    lines.append("1. Review the **lowest scoring domains** and identify quick wins (policies, processes, or configurations).")
    lines.append("2. For any **Critical/High vulnerabilities or patch gaps**, define specific remediation tasks with owners and deadlines.")
    lines.append("3. Use the **Vulnerability Register** and **Patch Register** to track remediation through to closure.")
    lines.append("4. Re-run this assessment after major improvements to measure progress over time.")
    lines.append("")
    lines.append("---")
    lines.append("_This report was generated by `score_vuln_patch_readiness.py`._")
    lines.append("")

    return "\n".join(lines)


# ---- CLI --------------------------------------------------------------------


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Calculate vulnerability & patch readiness score from a CSV of responses "
            "and generate a Markdown report."
        )
    )
    parser.add_argument(
        "--input",
        "-i",
        required=True,
        type=Path,
        help="Path to CSV file containing question_id,score responses.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("vuln_patch_readiness_report.md"),
        help="Path to write the Markdown report (default: vuln_patch_readiness_report.md).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)

    try:
        responses = load_responses(args.input)
    except Exception as e:
        sys.stderr.write(f"Error loading responses: {e}\n")
        return 1

    overall = calculate_overall_score(responses)
    domains = calculate_domain_scores(responses)

    # Console summary
    print("Vulnerability & Patch Readiness Summary")
    print("--------------------------------------")
    print(f"Input file      : {args.input}")
    print(f"Total score     : {overall.total_score} / {overall.max_score}")
    print(f"Overall %       : {overall.percentage:.1f}%")
    print(f"Maturity level  : {overall.maturity_level}")
    print()
    print("Domain scores:")
    for d in domains:
        print(f"- {d.name}: {d.score}/{d.max_score} ({d.percentage:.1f}%)")

    # Generate report
    try:
        report_text = generate_markdown_report(responses, overall, domains, args.input)
        args.output.write_text(report_text, encoding="utf-8")
        print()
        print(f"Markdown report written to: {args.output}")
    except Exception as e:
        sys.stderr.write(f"Error writing report: {e}\n")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
