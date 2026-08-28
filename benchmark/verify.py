import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

import os
import glob
import json
from pathlib import Path

project_root = str(Path(__file__).resolve().parent.parent)
if project_root not in sys.path:
    sys.path.append(project_root)


# LLM verification
def verify_with_llm(expected_cwe, expected_type, finding_title, finding_message, finding_cwes):
    try:
        from src.llm import fetch_llm
        prompt = f"""
            You are a vulnerability verification judge.
            The benchmark EXPECTED this vulnerability: CWE: {expected_cwe}, Type: {expected_type}
            The AI scanner FOUND this vulnerability on the exact same file:
            - Title: {finding_title}
            - Message: {finding_message}
            - Extracted CWEs: {finding_cwes}

            Please use Chain of Thought reasoning to determine if the AI's finding
            correctly describes or is a variant of the expected vulnerability.
            Return a JSON object with two fields:
            1. "reason": A string containing a step-by-step explanation of your thought process.
            2. "match": A boolean indicating whether it is a match.

            Example: {{"reason": "The expected vulnerability is X. The AI found Y. X and Y are related because... therefore it matches.", "match": true}}
        """
        result = fetch_llm(prompt=prompt, model=None, jfmt=True)
        return result.get("match", False)
    except Exception as error:
        print(f"[LLM Judge Error] {error}", file=sys.stderr)
        return False


# Manual verification
def verify_manually(expected_vuln, finding, is_sca_finding, target_path, target_basename, vuln_type):
    finding_path     = str(finding.get("path", "")).replace("\\", "/")
    finding_basename = Path(finding_path).name.lower()

    # Check if the vulnerability is in the same file
    same_file = target_path in finding_path or target_basename == finding_basename
    if not same_file:
        return False

    # SCA: match by CVE ID or package name
    if is_sca_finding:
        expected_cve    = expected_vuln.get("cve", "").upper()
        finding_package = str(finding.get("sca_package", "")).lower()
        finding_cves    = [str(cve).upper() for cve in finding.get("cve", [])]
        return expected_cve in finding_cves or vuln_type.lower() == finding_package

    # SAST: match by CWE, rule ID, title, or message
    expected_cwe    = expected_vuln.get("cwe", "").upper()
    finding_rule_id = str(finding.get("id", "")).upper()
    finding_title   = str(finding.get("title", "")).upper()
    finding_message = str(finding.get("message", "")).upper()

    finding_cwes = finding.get("cwe", [])
    cwe_matched = any(expected_cwe in str(cwe).upper() for cwe in finding_cwes)

    return (
        expected_cwe in finding_rule_id
        or expected_cwe in finding_title
        or expected_cwe in finding_message
        or vuln_type.upper() in finding_title
        or cwe_matched
    )


# Print project detection results
def render_results_table(project_name, details):
    print(f"\n--- PROJECT: {project_name.upper()} ---")
    print("-" * 115)
    print(f"| {'CWE/CVE':<15} | {'File':<40} | {'Type':<25} | {'Manual':<8} | {'AI':<8} |")
    print("-" * 115)
    for detail in details:
        cwe_or_cve = detail.get('cve') or detail.get('cwe', '')
        file_path  = detail.get('file', '')
        if len(file_path) > 37:
            file_path = "..." + file_path[-37:]
        vuln_type = detail.get('type', '')
        if len(vuln_type) > 22:
            vuln_type = vuln_type[:22] + "..."
        manual_result = "PASS" if detail.get('detected_manually') else "FAIL"
        ai_result     = "PASS" if detail.get('detected_by_ai') else "FAIL"
        print(f"| {cwe_or_cve:<15} | {file_path:<40} | {vuln_type:<25} | {manual_result:<8} | {ai_result:<8} |")
    print("-" * 115)


# Print final detection results
def render_final_summary(total_expected, total_manual, total_ai):
    manual_rate = (total_manual / total_expected * 100) if total_expected > 0 else 0
    ai_rate     = (total_ai     / total_expected * 100) if total_expected > 0 else 0
    system_rate = (manual_rate + ai_rate) / 2

    print("\n" + "=" * 50)
    print("RESULTS".center(50))
    print("=" * 50)
    print(f"Vulnerabilities : {total_expected}")
    print(f"Manual    : {total_manual} ({manual_rate:.1f}%)")
    print(f"AI        : {total_ai} ({ai_rate:.1f}%)")
    print("-" * 50)
    print(f"Rate : {system_rate:.1f}%".center(50))
    print("=" * 50 + "\n")


def main():
    benchmark_dir  = Path(__file__).resolve().parent
    total_expected = 0
    total_manual   = 0
    total_ai       = 0

    # Load global report if exists
    global_sast_findings = []
    global_reports_dir   = benchmark_dir.parent / "reports"
    if global_reports_dir.exists():
        global_report_files = glob.glob(str(global_reports_dir / "sinful_report_*.json"))
        if global_report_files:
            latest_global_report = max(global_report_files, key=os.path.getmtime)
            try:
                with open(latest_global_report, "r", encoding="utf-8") as file_handle:
                    global_scan = json.load(file_handle)
                    global_sast_findings = (
                        global_scan.get("data", {}).get("sast", [])
                        if "data" in global_scan
                        else global_scan.get("sast", [])
                    )
            except Exception:
                pass

    for project_dir in sorted(benchmark_dir.iterdir()):
        if not project_dir.is_dir():
            continue

        # Skip projects that have no ground-truth file
        ground_truth_file = project_dir / "vulnerabilities.json"
        if not ground_truth_file.exists():
            continue

        with open(ground_truth_file, "r", encoding="utf-8") as file_handle:
            ground_truth = json.load(file_handle)

        expected_vulns = ground_truth.get("expected", [])
        if not expected_vulns:
            continue

        all_findings = []
        report_found = False

        # Load per-project report if exists
        per_project_reports_dir  = project_dir / "reports"
        per_project_report_files = (
            glob.glob(str(per_project_reports_dir / "sinful_report_*.json"))
            if per_project_reports_dir.exists() else []
        )
        if per_project_report_files:
            report_found  = True
            latest_report = max(per_project_report_files, key=os.path.getmtime)
            try:
                with open(latest_report, "r", encoding="utf-8") as file_handle:
                    scan_result = json.load(file_handle)
                    sast_findings = (
                        scan_result.get("data", {}).get("sast", [])
                        if "data" in scan_result
                        else scan_result.get("sast", [])
                    )
                    sca_findings = (
                        scan_result.get("data", {}).get("sca", [])
                        if "data" in scan_result
                        else scan_result.get("sca", [])
                    )
                    all_findings.extend(sast_findings)

                    seen_packages = set()
                    for sca_entry in sca_findings:
                        package_name = sca_entry.get("package", "")
                        if package_name in seen_packages:
                            continue
                        seen_packages.add(package_name)
                        all_findings.append({
                            "path":        sca_entry.get("manifest_file", ""),
                            "id":          sca_entry.get("vuln_id", ""),
                            "title":       package_name,
                            "sca_package": package_name,
                            "cve":         sca_entry.get("cve", []),
                        })
            except Exception:
                pass

        # Filter results from global report by project reports
        elif global_sast_findings:
            project_path_marker = f"/benchmark/{project_dir.name}/"
            project_name_lower  = project_dir.name.lower()
            matched_global = []
            for global_finding in global_sast_findings:
                normalized_path = str(global_finding.get("path", "")).replace("\\", "/")
                if project_path_marker in normalized_path or project_name_lower in normalized_path.lower():
                    matched_global.append(global_finding)
                    report_found = True
            all_findings = matched_global

        # No report found
        if not report_found:
            no_report_details = []
            for expected_vuln in expected_vulns:
                entry = expected_vuln.copy()
                entry['detected_manually'] = False
                entry['detected_by_ai']    = False
                no_report_details.append(entry)
            render_results_table(project_dir.name + " NO REPORT", no_report_details)
            continue

        # Score expected vulnerabilities based on existed vulnerabilities
        project_details = []
        for expected_vuln in expected_vulns:
            is_sca_vuln     = "cve" in expected_vuln
            expected_cwe    = expected_vuln.get("cwe", "").upper()
            target_file     = expected_vuln.get("file", "")
            vuln_type       = expected_vuln.get("type", "")
            target_basename = Path(target_file).name.lower()

            detected_manually = False
            detected_by_ai    = False

            for finding in all_findings:
                # Manual verification
                if verify_manually(expected_vuln, finding, is_sca_vuln, target_file, target_basename, vuln_type):
                    detected_manually = True
                    detected_by_ai    = True
                    break

                # LLM verification
                finding_path     = str(finding.get("path", "")).replace("\\", "/")
                finding_basename = Path(finding_path).name.lower()
                same_file        = target_file in finding_path or target_basename == finding_basename

                if same_file and not is_sca_vuln and not detected_by_ai:
                    finding_title   = str(finding.get("title",   "")).upper()
                    finding_message = str(finding.get("message", "")).upper()

                    finding_cwes = finding.get("cwe", [])

                    if verify_with_llm(expected_cwe, vuln_type, finding_title, finding_message, finding_cwes):
                        detected_by_ai = True
                        break

            if detected_manually:
                total_manual += 1
            if detected_by_ai:
                total_ai += 1
            total_expected += 1

            entry = expected_vuln.copy()
            entry['detected_manually'] = detected_manually
            entry['detected_by_ai']    = detected_by_ai
            project_details.append(entry)

        render_results_table(project_dir.name, project_details)

    render_final_summary(total_expected, total_manual, total_ai)


if __name__ == "__main__":
    main()