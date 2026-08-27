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

def extract_cwes(flaw):
    cwes = flaw.get("cwe", [])
    if isinstance(cwes, str):
        cwes = [cwes]
    elif not isinstance(cwes, list):
        cwes = []
        
    meta = flaw.get("metadata", {})
    mcwe = meta.get("cwe", [])
    if isinstance(mcwe, str):
        cwes.append(mcwe)
    elif isinstance(mcwe, list):
        cwes.extend(mcwe)
    return cwes

def verify_ai(expected_cwe, expected_type, ai_title, ai_msg, ai_class, ai_cwes):
    try:
        from src.llm import fetch_llm
        prompt = f"""
            You are a vulnerability verification judge. 
            The benchmark EXPECTED this vulnerability: CWE: {expected_cwe}, Type: {expected_type}
            The AI scanner FOUND this vulnerability on the exact same file:
            - Title: {ai_title}
            - Message: {ai_msg}
            - Class: {ai_class}
            - Extracted CWEs: {ai_cwes}

            Please use Chain of Thought reasoning to determine if the AI's finding correctly describes or is a variant of the expected vulnerability.
            Return a JSON object with two fields:
            1. "reasoning": A string containing a step-by-step explanation of your thought process.
            2. "match": A boolean indicating whether it is a match.
            
            Example: {{"reasoning": "The expected vulnerability is X. The AI found Y. X and Y are related because... therefore it matches.", "match": true}}
        """
        res = fetch_llm(prompt=prompt, model=None, jfmt=True)
        return res.get("match", False)
    except Exception as e:
        print(f"[AI Error] {e}", file=sys.stderr)
        return False

def verify_manual(v, flaw, is_sca, target, target_basename, vtype):
    fpath = str(flaw.get("path", "")).replace("\\", "/")
    fpath_basename = Path(fpath).name.lower()
    
    path_match = target in fpath or target_basename == fpath_basename
    
    if not path_match:
        return False
        
    if is_sca:
        expected_cve = v.get("cve", "").upper()
        fpkg = str(flaw.get("sca_package", "")).lower()
        fcves = [str(x).upper() for x in flaw.get("cve", [])]
        cve_match = expected_cve in fcves
        pkg_match = vtype.lower() == fpkg
        return cve_match or pkg_match

    cwe = v.get("cwe", "").upper()
    fid = str(flaw.get("id", "")).upper()
    ftitle = str(flaw.get("title", "")).upper()
    fmsg = str(flaw.get("message", "")).upper()
    
    fcwes = extract_cwes(flaw)
    cwe_ids = flaw.get("cwe_ids", [])
    cwe_id_match = any(cwe == f"CWE-{c_id}" for c_id in cwe_ids) if isinstance(cwe_ids, list) else False
    has_cwe = cwe_id_match or any(cwe in str(c).upper() for c in fcwes)
    fvuln_class = str(flaw.get("vuln_class", "")).upper()
    
    return (cwe in fid or cwe in ftitle or cwe in fmsg or vtype.upper() in ftitle or has_cwe or cwe in fvuln_class or vtype.upper() in fvuln_class)

def render_table(name, details):
    print(f"\n--- PROJECT: {name.upper()} ---")
    print("-" * 115)
    print(f"| {'CWE/CVE':<15} | {'File':<40} | {'Type':<25} | {'Manual':<8} | {'AI':<8} |")
    print("-" * 115)
    for d in details:
        cwe_cve = d.get('cve') or d.get('cwe', '')
        f = d.get('file', '')
        if len(f) > 37:
            f = "..." + f[-37:]
        vtype = d.get('type', '')
        if len(vtype) > 22:
            vtype = vtype[:22] + "..."
            
        man_res = "PASS" if d.get('det_manual') else "FAIL"
        ai_res = "PASS" if d.get('det_ai') else "FAIL"
        print(f"| {cwe_cve:<15} | {f:<40} | {vtype:<25} | {man_res:<8} | {ai_res:<8} |")
    print("-" * 115)

def render_conclusion(total_exp, total_manual, total_ai):
    man_rate = (total_manual / total_exp * 100) if total_exp > 0 else 0
    ai_rate = (total_ai / total_exp * 100) if total_exp > 0 else 0
    sys_rate = (man_rate + ai_rate) / 2

    print("\n" + "=" * 50)
    print("FINAL".center(50))
    print("=" * 50)
    print(f"Total Vulnerabilities: {total_exp}")
    print(f"Detected by Manual: {total_manual} ({man_rate:.1f}%)")
    print(f"Detected by AI:     {total_ai} ({ai_rate:.1f}%)")
    print("-" * 50)
    print(f"System Detection Rate: {sys_rate:.1f}%".center(50))
    print("=" * 50 + "\n")

def main():
    root = Path(__file__).resolve().parent
    total_exp = 0
    total_manual = 0
    total_ai = 0
    
    global_findings = []
    root_reports = root.parent / "reports"
    if root_reports.exists():
        gfiles = glob.glob(str(root_reports / "sinful_report_*.json"))
        if gfiles:
            glatest = max(gfiles, key=os.path.getmtime)
            try:
                with open(glatest, "r", encoding="utf-8") as f:
                    gscan = json.load(f)
                    global_findings = gscan.get("data", {}).get("sast", []) if "data" in gscan else gscan.get("sast", [])
            except Exception:
                pass
                
    for proj in sorted(root.iterdir()):
        if not proj.is_dir():
            continue
            
        tfile = proj / "vulnerabilities.json"
        if not tfile.exists():
            continue
            
        with open(tfile, "r", encoding="utf-8") as f:
            truth = json.load(f)
            
        vulns = truth.get("expected", [])
        if not vulns:
            continue
            
        findings = []
        has_report = False
        
        rdir = proj / "reports"
        rfiles = glob.glob(str(rdir / "sinful_report_*.json")) if rdir.exists() else []
        if rfiles:
            has_report = True
            latest = max(rfiles, key=os.path.getmtime)
            try:
                with open(latest, "r", encoding="utf-8") as f:
                    lscan = json.load(f)
                    findings = lscan.get("data", {}).get("sast", []) if "data" in lscan else lscan.get("sast", [])
                    cves = lscan.get("data", {}).get("sca", []) if "data" in lscan else lscan.get("sca", [])

                    seen_sca = set()
                    for c in cves:
                        pkg = c.get("package", "")
                        if pkg in seen_sca:
                            continue
                        seen_sca.add(pkg)
                        findings.append({
                            "path": c.get("manifest_file", ""),
                            "id": c.get("vuln_id", ""),
                            "title": pkg,
                            "sca_package": pkg,
                            "cve": c.get("cve", []),
                        })
            except Exception:
                pass
        elif global_findings:
            proj_marker = f"/benchmark/{proj.name}/"
            proj_name_lower = proj.name.lower()
            proj_findings = []
            for gf in global_findings:
                fpath_norm = str(gf.get("path", "")).replace("\\", "/")
                if proj_marker in fpath_norm or proj_name_lower in fpath_norm.lower():
                    proj_findings.append(gf)
                    has_report = True
            findings = proj_findings
            
        if not has_report:
            details = []
            for v in vulns:
                v_entry = v.copy()
                v_entry['det_manual'] = False
                v_entry['det_ai'] = False
                details.append(v_entry)
            render_table(proj.name + " (NO REPORT)", details)
            continue
            
        details = []
        for v in vulns:
            is_sca = "cve" in v
            cwe = v.get("cwe", "").upper()
            target = v.get("file", "")
            vtype = v.get("type", "")
            target_basename = Path(target).name.lower()
            
            det_manual = False
            det_ai = False
            
            for flaw in findings:
                if verify_manual(v, flaw, is_sca, target, target_basename, vtype):
                    det_manual = True
                    det_ai = True
                    break
                    
                fpath = str(flaw.get("path", "")).replace("\\", "/")
                fpath_basename = Path(fpath).name.lower()
                path_match = target in fpath or target_basename == fpath_basename
                if path_match and not is_sca and not det_ai:
                    fid = str(flaw.get("id", "")).upper()
                    ftitle = str(flaw.get("title", "")).upper()
                    fmsg = str(flaw.get("message", "")).upper()
                    fvuln_class = str(flaw.get("vuln_class", "")).upper()
                    cwe_ids = flaw.get("cwe_ids", [])
                    if verify_ai(cwe, vtype, ftitle, fmsg, fvuln_class, cwe_ids):
                        det_ai = True
                        break
                        
            if det_manual:
                total_manual += 1
            if det_ai:
                total_ai += 1
            total_exp += 1
            
            v_entry = v.copy()
            v_entry['det_manual'] = det_manual
            v_entry['det_ai'] = det_ai
            details.append(v_entry)
            
        render_table(proj.name, details)
        
    render_conclusion(total_exp, total_manual, total_ai)

if __name__ == "__main__":
    main()
