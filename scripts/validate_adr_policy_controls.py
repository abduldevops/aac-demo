import os, re, glob, json, subprocess, sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import yaml  # pyyaml

# ----------------------------
# Models
# ----------------------------

@dataclass
class ADR:
    path: str
    adr_id: str
    title: str
    intent: Dict[str, Any]
    governance: Dict[str, Any]
    raw_markdown: str

@dataclass
class ControlDef:
    control_id: str
    name: str
    applies_to: List[str]               # ["terraform", "java", "repo", ...]
    evidence: List[Dict[str, Any]]      # [{"tool":"tfsec","report":"reports/tfsec.json"}]
    evaluation: Dict[str, Any]          # {"evaluator":"tfsec", "params":{...}}
    gate: Dict[str, Any]                # {"required": true, "fail_on": {...}}

@dataclass
class ControlResult:
    control_id: str
    passed: bool
    severity: str
    findings: List[str]
    evidence_used: List[str]
    adr_ids: List[str]                  # which ADRs demanded this control


# ----------------------------
# ADR parsing
# ----------------------------

FRONT_MATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

def parse_adr(path: str) -> ADR:
    print("in parse_adr")
    print(ADR)
    ptint(path)
    text = open(path, "r", encoding="utf-8").read()
    print(text)
    m = FRONT_MATTER_RE.match(text)
    print(m)
    if not m:
        raise ValueError(f"ADR missing YAML front matter: {path}")
    meta = yaml.safe_load(m.group(1)) or {}
    print(meta)
    return ADR(
        path=path,
        adr_id=meta.get("adr_id") or os.path.basename(path).split("-")[0],
        title=meta.get("title", ""),
        intent=meta.get("intent", {}) or {},
        governance=meta.get("governance", {}) or {},
        raw_markdown=text,
    )

def load_adrs(adrs_dir="adr") -> List[ADR]:
    print("in load_adrs")
    print(adrs_dir)
    paths = sorted(glob.glob(os.path.join(adrs_dir, "*.md")))
    print(paths)
    print("in load_adrs->1")
    return [parse_adr(p) for p in paths]

def derive_required_controls(adrs: List[ADR]) -> Dict[str, List[str]]:
    """
    Returns: control_id -> list of ADR IDs that require it
    """
    mapping: Dict[str, List[str]] = {}
    for adr in adrs:
        controls = (adr.governance.get("controls") or [])
        for cid in controls:
            mapping.setdefault(cid, []).append(adr.adr_id)
    return mapping


# ----------------------------
# Control catalogue loading
# ----------------------------

def load_control_def(control_id: str, controls_dir="controls") -> ControlDef:
    folder = os.path.join(controls_dir, f"{control_id}-control")
    path = os.path.join(folder, "control.yaml")
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing control definition for {control_id}: {path}")
    doc = yaml.safe_load(open(path, "r", encoding="utf-8")) or {}

    return ControlDef(
        control_id=doc["id"],
        name=doc.get("name", ""),
        applies_to=doc.get("applies_to", []),
        evidence=doc.get("evidence", []),
        evaluation=doc.get("evaluation", {}),
        gate=doc.get("gate", {"required": True}),
    )


# ----------------------------
# Evidence generation (run once per tool bundle)
# ----------------------------

def run(cmd: List[str], cwd: Optional[str] = None) -> None:
    r = subprocess.run(cmd, cwd=cwd, text=True, capture_output=True)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        raise SystemExit(r.returncode)

def ensure_reports():
    os.makedirs("reports", exist_ok=True)

def generate_terraform_evidence():
    # assumes infra/ exists
    ensure_reports()
    # fmt/validate
    run(["terraform", "fmt", "-check", "-recursive"], cwd="infra")
    run(["terraform", "init", "-backend=false"], cwd="infra")
    run(["terraform", "validate"], cwd="infra")
    # plan + json
    run(["terraform", "plan", "-out=tfplan"], cwd="infra")
    plan_json = subprocess.check_output(["terraform", "show", "-json", "tfplan"], cwd="infra", text=True)
    with open("reports/tfplan.json", "w", encoding="utf-8") as f:
        f.write(plan_json)

def generate_java_evidence():
    ensure_reports()
    # ArchUnit should run inside unit tests.
    run(["mvn", "-q", "test"], cwd="microservice")
    # optional: build surefire summary json for easier parsing
    # (you can implement a small parser that reads surefire XML and writes reports/surefire-summary.json)

def generate_security_evidence():
    ensure_reports()
    # gitleaks optional
    # run(["gitleaks", "detect", "--report-format", "json", "--report-path", "reports/gitleaks.json"])

def generate_tool_reports(tool_names: List[str]):
    """
    Run only what is needed. Keep this mapping canonical.
    """
    if any(t in tool_names for t in ["terraform-plan", "tfsec", "checkov", "conftest-tfplan"]):
        generate_terraform_evidence()

    if "tfsec" in tool_names:
        run(["tfsec", "infra", "--format", "json", "--out", "reports/tfsec.json"])

    if "checkov" in tool_names:
        out = subprocess.check_output(["checkov", "-d", "infra", "-o", "json"], text=True)
        open("reports/checkov.json", "w", encoding="utf-8").write(out)

    if "conftest-tfplan" in tool_names:
        out = subprocess.check_output(["conftest", "test", "reports/tfplan.json", "-p", "policies/terraform", "-o", "json"], text=True)
        open("reports/opa-tfplan.json", "w", encoding="utf-8").write(out)

    if any(t in tool_names for t in ["mvn-test", "archunit"]):
        generate_java_evidence()

    if any(t in tool_names for t in ["gitleaks"]):
        generate_security_evidence()


# ----------------------------
# Evaluators (deterministic)
# ----------------------------

def severity_rank(sev: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(sev.upper(), 0)

def eval_tfsec(control: ControlDef) -> Tuple[bool, str, List[str], List[str]]:
    report = next((e["report"] for e in control.evidence if e.get("tool") == "tfsec"), "reports/tfsec.json")
    if not os.path.exists(report):
        return False, "HIGH", [f"Missing tfsec report: {report}"], [report]
    data = json.load(open(report, "r", encoding="utf-8"))

    findings = data.get("results") or data.get("findings") or []
    params = control.evaluation.get("params", {})
    min_sev = params.get("min_severity", "HIGH")
    include_rule_ids = set(params.get("include_rule_ids", []))  # optional filter

    bad = []
    for f in findings:
        rid = f.get("rule_id") or f.get("ruleID") or ""
        sev = (f.get("severity") or "").upper()
        if include_rule_ids and rid not in include_rule_ids:
            continue
        if severity_rank(sev) >= severity_rank(min_sev):
            desc = f.get("description") or f.get("long_id") or ""
            bad.append(f"tfsec {rid} {sev}: {desc}".strip())

    passed = len(bad) == 0
    worst = "LOW"
    for b in bad:
        # crude worst severity inference
        if "CRITICAL" in b: worst = "CRITICAL"
        elif "HIGH" in b and worst != "CRITICAL": worst = "HIGH"
        elif "MEDIUM" in b and worst not in ["CRITICAL", "HIGH"]: worst = "MEDIUM"

    return passed, worst if not passed else "LOW", bad, [report]

def eval_conftest(control: ControlDef) -> Tuple[bool, str, List[str], List[str]]:
    report = next((e["report"] for e in control.evidence if e.get("tool") == "conftest"), "reports/opa-tfplan.json")
    if not os.path.exists(report):
        return False, "HIGH", [f"Missing conftest report: {report}"], [report]
    data = json.load(open(report, "r", encoding="utf-8"))
    params = control.evaluation.get("params", {})
    required_rule_ids = set(params.get("rule_ids", []))  # optional: only consider certain deny codes

    bad = []
    # conftest json format varies; treat any "failures" as violations
    for entry in data:
        failures = entry.get("failures", [])
        for f in failures:
            rid = f.get("metadata", {}).get("id") or f.get("code") or ""
            msg = f.get("msg") or ""
            if required_rule_ids and rid not in required_rule_ids:
                continue
            bad.append(f"opa {rid}: {msg}".strip())

    passed = len(bad) == 0
    return passed, "HIGH" if not passed else "LOW", bad, [report]

def eval_surefire_testnames(control: ControlDef) -> Tuple[bool, str, List[str], List[str]]:
    # simplest approach: require certain test classes exist and passed
    # better: parse surefire XML files under microservice/target/surefire-reports/
    params = control.evaluation.get("params", {})
    required = params.get("required_test_classes", [])
    reports_dir = "microservice/target/surefire-reports"
    if not os.path.isdir(reports_dir):
        return False, "HIGH", [f"Missing surefire reports dir: {reports_dir}"], [reports_dir]

    # naive: check filenames contain required class names and no failures
    files = os.listdir(reports_dir)
    missing = []
    for cls in required:
        # surefire uses TEST-<fqcn>.xml
        expected = f"TEST-{cls}.xml"
        if expected not in files:
            missing.append(f"Missing required test report: {expected}")

    if missing:
        return False, "HIGH", missing, [reports_dir]

    # optional: parse XML to ensure failures=0
    # (left as enhancement; implement if you want strict gating)

    return True, "LOW", [], [reports_dir]


EVALUATORS = {
    "tfsec": eval_tfsec,
    "conftest": eval_conftest,
    "surefire_testnames": eval_surefire_testnames,
}


def evaluate_control(control: ControlDef) -> Tuple[bool, str, List[str], List[str]]:
    ev = control.evaluation.get("evaluator")
    if ev not in EVALUATORS:
        return False, "HIGH", [f"Unknown evaluator '{ev}' for control {control.control_id}"], []
    return EVALUATORS[ev](control)


# ----------------------------
# LLM narrative (optional, non-gating)
# ----------------------------

def llm_enhance_report(adrs: List[ADR], results: List[ControlResult]) -> Optional[str]:
    """
    Intentionally left as an integration hook.
    This should NEVER affect pass/fail. It produces narrative only.
    """
    # You can implement this using your internal LLM endpoint or OpenAI API.
    # Provide the model with:
    # - ADR intent sections (summary + key constraints)
    # - control results (failures + evidence)
    #
    # Return markdown text.
    return None


# ----------------------------
# Main
# ----------------------------

def main():
    adrs = load_adrs("adr")
    ptint(adrs)
    required_map = derive_required_controls(adrs)  # control_id -> [adr_id]
    print(required_map)

    # load all control defs
    control_defs: List[ControlDef] = [load_control_def(cid) for cid in sorted(required_map.keys())]

    # derive needed tool reports from controls
    tool_set = set()
    for c in control_defs:
        for ev in c.evidence:
            tool = ev.get("tool")
            if tool:
                tool_set.add(tool)

    # map evidence tools to pipeline tool bundles
    bundles = set()
    if any(t in tool_set for t in ["tfsec", "checkov", "conftest"]):
        bundles.add("terraform-plan")
    if "tfsec" in tool_set:
        bundles.add("tfsec")
    if "checkov" in tool_set:
        bundles.add("checkov")
    if "conftest" in tool_set:
        bundles.add("conftest-tfplan")
    if any(t in tool_set for t in ["mvn", "surefire"]):
        bundles.add("mvn-test")

    generate_tool_reports(sorted(bundles))

    # evaluate
    results: List[ControlResult] = []
    for c in control_defs:
        passed, sev, findings, evidence_used = evaluate_control(c)
        results.append(ControlResult(
            control_id=c.control_id,
            passed=passed,
            severity=sev,
            findings=findings,
            evidence_used=evidence_used,
            adr_ids=required_map.get(c.control_id, []),
        ))

    # outputs
    ensure_reports()
    json_out = {
        "adrs": [{"adr_id": a.adr_id, "title": a.title, "path": a.path} for a in adrs],
        "results": [r.__dict__ for r in results],
        "summary": {
            "total_controls": len(results),
            "failed_controls": sum(1 for r in results if not r.passed),
        }
    }
    open("reports/control-results.json", "w", encoding="utf-8").write(json.dumps(json_out, indent=2))

    # simple markdown report
    lines = []
    lines.append("# ADR Governance Control Report\n")
    lines.append("## Controls derived from ADRs\n")
    for r in results:
        status = "✅ PASS" if r.passed else "❌ FAIL"
        lines.append(f"- **{r.control_id}** {status} (severity: {r.severity}) — required by: {', '.join(r.adr_ids)}")
        for f in r.findings[:10]:
            lines.append(f"  - {f}")
    open("reports/control-results.md", "w", encoding="utf-8").write("\n".join(lines))

    # LLM narrative (optional)
    narrative = llm_enhance_report(adrs, results)
    if narrative:
        open("reports/adr-governance-report.md", "w", encoding="utf-8").write(narrative)

    # deterministic gate
    failed_required = []
    for cdef, r in zip(control_defs, results):
        required = cdef.gate.get("required", True)
        if required and not r.passed:
            failed_required.append(r.control_id)

    if failed_required:
        print("CONTROL GATE FAILED:", ", ".join(failed_required))
        sys.exit(1)

    print("CONTROL GATE PASSED")
    sys.exit(0)

if __name__ == "__main__":
    main()
