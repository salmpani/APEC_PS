"""Scanner module for PQC risk triage prototype.

The scanner combines lightweight static analysis, configuration parsing,
certificate inspection, and small-binary signature scanning. It is still a
research/demo tool, but it models risk with enough context for the agent layer
to reason about priority and migration complexity.
"""

import ast
import concurrent.futures
import json
import os
import re
import socket
import ssl
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import yaml


VULNERABLE_ALGORITHMS = {
    "RSA-2048": ("medium", "RSA 2048 is vulnerable to sufficiently large quantum computers; prefer hybrid PQC or larger transitional keys"),
    "RSA": ("medium", "Generic RSA use may indicate RSA-based encryption or signing exposed to quantum attacks"),
    "DSA": ("medium", "Finite-field DSA signatures are not quantum-safe"),
    "ECDH": ("medium", "Elliptic-curve Diffie-Hellman key exchange is not quantum-safe"),
    "ECDSA": ("medium", "Elliptic-curve digital signatures are not quantum-safe"),
    "SHA1": ("high", "SHA-1 is broken for collision resistance and should be retired"),
    "TLS1.0": ("high", "TLS 1.0 is obsolete and vulnerable"),
    "TLS1.1": ("high", "TLS 1.1 is obsolete and vulnerable"),
    "TLSv1.0": ("high", "TLS 1.0 is obsolete and vulnerable"),
    "TLSv1.1": ("high", "TLS 1.1 is obsolete and vulnerable"),
    "tls_key_exchange: ECDHE-RSA": ("medium", "ECDHE-RSA is not post-quantum secure; consider hybrid PQC key exchange"),
    "certificate_signature: ECDSA": ("medium", "ECDSA signatures are not quantum-safe; consider ML-DSA or SLH-DSA"),
}

SEVERITY_WEIGHTS = {"low": 1, "medium": 2, "high": 3}
RISK_SCORE_TO_SEVERITY = [(8, "high"), (4, "medium"), (0, "low")]
TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".c", ".cpp",
    ".cs", ".rs", ".php", ".tf", ".hcl", ".sh", ".txt", ".cfg", ".ini", ".xml",
}
CONFIG_EXTENSIONS = {".yaml", ".yml", ".json"}
CERT_EXTENSIONS = {".pem", ".crt", ".cer"}
MANIFEST_NAMES = {"requirements.txt", "package.json", "composer.json", "pom.xml", "go.mod"}
BINARY_EXTENSIONS = {".der", ".p12", ".pfx", ".jks", ".so", ".dll", ".dylib", ".a", ".jar", ".war", ".ear"}


def _severity_from_score(score: int) -> str:
    for threshold, severity in RISK_SCORE_TO_SEVERITY:
        if score >= threshold:
            return severity
    return "low"


def _make_finding(
    path: str,
    line_no: Optional[int],
    finding_type: str,
    algorithm: str,
    description: str,
    severity: str,
    evidence: Optional[str] = None,
    confidence: str = "medium",
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    context = context or {}
    base_score = SEVERITY_WEIGHTS.get(severity, 1) * 2
    retention_years = int(context.get("retention_years") or 0)
    migration_complexity = context.get("migration_complexity", "medium")
    business_impact = context.get("business_impact", "moderate")

    if retention_years >= 10:
        base_score += 2
    elif retention_years >= 5:
        base_score += 1
    if business_impact in {"high", "critical"}:
        base_score += 2
    elif business_impact == "moderate":
        base_score += 1
    if migration_complexity == "high":
        base_score += 1

    return {
        "file": path,
        "line_no": line_no,
        "type": finding_type,
        "algorithm": algorithm,
        "description": description,
        "severity": _severity_from_score(base_score),
        "base_severity": severity,
        "risk_score": base_score,
        "confidence": confidence,
        "evidence": evidence,
        "retention_years": retention_years or None,
        "business_impact": business_impact,
        "migration_complexity": migration_complexity,
    }


def _extract_context_from_text(text: str) -> Dict[str, Any]:
    retention_match = re.search(r"(?:retention(?:_years)?|DATA_RETENTION_YEARS)\D{0,20}(\d{1,3})", text, re.IGNORECASE)
    lower = text.lower()
    business_impact = "low"
    for impact, signals in {
        "critical": ["secret", "private_key", "root_ca", "signing_key"],
        "high": ["payment", "customer", "pii", "personal", "health", "financial"],
        "moderate": ["internal", "service", "token"],
    }.items():
        if any(signal in lower for signal in signals):
            business_impact = impact
            break
    return {
        "retention_years": int(retention_match.group(1)) if retention_match else 0,
        "business_impact": business_impact,
    }


def _line_for_node(source: str, node: ast.AST) -> str:
    if hasattr(node, "lineno"):
        lines = source.splitlines()
        if 1 <= node.lineno <= len(lines):
            return lines[node.lineno - 1].strip()
    return ""


class _PythonCryptoVisitor(ast.NodeVisitor):
    def __init__(self, path: str, source: str, context: Dict[str, Any]) -> None:
        self.path = path
        self.source = source
        self.context = context
        self.aliases: Dict[str, str] = {}
        self.findings: List[Dict[str, Any]] = []

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f"{module}.{alias.name}"
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        dotted = self._name(node.func).lower()
        checks: List[Tuple[str, str]] = [
            ("rsa.generate_private_key", "RSA"),
            ("ec.generate_private_key", "ECDSA"),
            ("dsa.generate_private_key", "DSA"),
            ("ecdh", "ECDH"),
            ("sha1", "SHA1"),
        ]
        for needle, algorithm in checks:
            if needle in dotted:
                sev, desc = VULNERABLE_ALGORITHMS.get(algorithm, ("medium", f"Detected {algorithm}"))
                local_context = dict(self.context)
                local_context["migration_complexity"] = "high" if algorithm in {"RSA", "ECDSA", "ECDH"} else "medium"
                self.findings.append(
                    _make_finding(
                        self.path,
                        getattr(node, "lineno", None),
                        "ast_crypto_call",
                        algorithm,
                        desc,
                        sev,
                        evidence=_line_for_node(self.source, node),
                        confidence="high",
                        context=local_context,
                    )
                )
        self.generic_visit(node)

    def _name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{self._name(node.value)}.{node.attr}"
        if isinstance(node, ast.Call):
            return self._name(node.func)
        return ""


def _scan_python_ast(path: str, content: str, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []
    visitor = _PythonCryptoVisitor(path, content, context)
    visitor.visit(tree)
    return visitor.findings


def _scan_language_heuristics(path: str, lines: List[str], context: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    library_patterns = [
        (r"crypto\.generateKeyPairSync\(['\"]rsa", "RSA", "js_crypto_call"),
        (r"crypto\.createSign\(['\"].*sha1", "SHA1", "js_crypto_call"),
        (r"KeyPairGenerator\.getInstance\(['\"]RSA", "RSA", "java_crypto_call"),
        (r"Signature\.getInstance\(['\"]SHA1", "SHA1", "java_crypto_call"),
        (r"ecdsa\.GenerateKey|elliptic\.P256", "ECDSA", "go_crypto_call"),
        (r"rsa\.GenerateKey", "RSA", "go_crypto_call"),
        (r"OpenSSL::PKey::RSA|OpenSSL::PKey::EC", "RSA", "ruby_crypto_call"),
    ]
    for idx, line in enumerate(lines, start=1):
        for regex, algorithm, finding_type in library_patterns:
            if re.search(regex, line, re.IGNORECASE):
                sev, desc = VULNERABLE_ALGORITHMS.get(algorithm, ("medium", f"Detected {algorithm}"))
                findings.append(
                    _make_finding(path, idx, finding_type, algorithm, desc, sev, evidence=line.strip(), context=context)
                )
    return findings


def _analyse_certificate(path: str) -> List[Dict[str, Any]]:
    """Inspect PEM/CRT certificates with cryptography when available."""
    findings: List[Dict[str, Any]] = []
    content = ""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        content = ""

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        raw = Path(path).read_bytes()
        cert = x509.load_pem_x509_certificate(raw) if b"BEGIN CERTIFICATE" in raw else x509.load_der_x509_certificate(raw)
        public_key = cert.public_key()
        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            algorithm = "RSA-2048" if key_size <= 2048 else "RSA"
            sev, desc = VULNERABLE_ALGORITHMS.get(algorithm, VULNERABLE_ALGORITHMS["RSA"])
            findings.append(_make_finding(path, None, "certificate_public_key", algorithm, desc, sev, evidence=f"RSA public key {key_size} bits", confidence="high"))
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            sev, desc = VULNERABLE_ALGORITHMS["ECDSA"]
            findings.append(_make_finding(path, None, "certificate_public_key", "ECDSA", desc, sev, evidence=public_key.curve.name, confidence="high"))

        sig_name = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else ""
        if "SHA1" in sig_name:
            sev, desc = VULNERABLE_ALGORITHMS["SHA1"]
            findings.append(_make_finding(path, None, "certificate_signature", "SHA1", desc, sev, evidence=sig_name, confidence="high"))
        return findings
    except Exception:
        pass

    patterns = {
        r"BEGIN RSA": "RSA",
        r"BEGIN EC": "ECDSA",
        r"Public-Key": "RSA",
        r"ECDSA": "ECDSA",
    }
    for regex, algo in patterns.items():
        if re.search(regex, content, re.IGNORECASE):
            sev, desc = VULNERABLE_ALGORITHMS.get(algo, ("medium", f"Detected {algo}"))
            findings.append(_make_finding(path, None, "certificate", algo, desc, sev, evidence=regex, confidence="medium"))

    for line_no, line in enumerate(content.splitlines(), start=1):
        for key, (sev, desc) in VULNERABLE_ALGORITHMS.items():
            if key.startswith("certificate_signature"):
                _, val = key.split(": ")
                if val.lower() in line.lower():
                    findings.append(_make_finding(path, line_no, "certificate_signature", val, desc, sev, evidence=line.strip()))
    return findings


def _scan_text_file(path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return findings

    content = "".join(lines)
    context = _extract_context_from_text(content)
    if path.lower().endswith(".py"):
        findings.extend(_scan_python_ast(path, content, context))
    findings.extend(_scan_language_heuristics(path, lines, context))

    suffix = Path(path).suffix.lower()
    broad_source_algorithms = {"RSA", "ECDSA", "ECDH", "DSA"}
    for idx, line in enumerate(lines, start=1):
        stripped = line.strip()
        for pattern, (sev, desc) in VULNERABLE_ALGORITHMS.items():
            if ": " in pattern:
                continue
            if suffix in {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".c", ".cpp", ".cs", ".rs", ".php"} and pattern in broad_source_algorithms:
                continue
            if re.search(rf"(?<![A-Za-z0-9_-]){re.escape(pattern)}(?![A-Za-z0-9_-])", stripped, re.IGNORECASE):
                findings.append(_make_finding(path, idx, "crypto_algorithm", pattern, desc, sev, evidence=stripped, context=context))
        if suffix != ".py" and re.search(r"rsa\.generate_private_key", stripped, re.IGNORECASE):
            sev, desc = VULNERABLE_ALGORITHMS["RSA"]
            findings.append(_make_finding(path, idx, "crypto_algorithm", "RSA", desc, sev, evidence=stripped, context=context))
        if suffix != ".py" and re.search(r"ec\.generate_private_key", stripped, re.IGNORECASE):
            sev, desc = VULNERABLE_ALGORITHMS["ECDSA"]
            findings.append(_make_finding(path, idx, "crypto_algorithm", "ECDSA", desc, sev, evidence=stripped, context=context))
    return findings


def _scan_yaml_json(path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f)
    except Exception:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except Exception:
            return findings
    if not isinstance(data, dict):
        return findings

    context = {
        "retention_years": int(data.get("retention_years") or data.get("data_retention_years") or 0),
        "business_impact": "high" if any(signal in str(data).lower() for signal in ("payment", "customer", "pii", "health")) else "moderate",
        "migration_complexity": "medium",
    }

    def walk(obj: Any, parent_key: str = "") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                key_path = f"{parent_key}.{key}" if parent_key else str(key)
                if isinstance(value, (dict, list)):
                    walk(value, key_path)
                    continue
                val_str = str(value)
                matched_field_specific = False
                for key_alg, (sev, desc) in VULNERABLE_ALGORITHMS.items():
                    if ": " not in key_alg:
                        continue
                    field, expected = key_alg.split(": ")
                    if str(key).lower() == field.lower() and expected.lower() == val_str.lower():
                        findings.append(_make_finding(path, None, field, expected, desc, sev, evidence=f"{key_path}: {val_str}", context=context))
                        matched_field_specific = True
                for key_alg, (sev, desc) in VULNERABLE_ALGORITHMS.items():
                    if ": " in key_alg:
                        continue
                    elif not matched_field_specific and re.search(rf"(?<![A-Za-z0-9_-]){re.escape(key_alg)}(?![A-Za-z0-9_-])", val_str, re.IGNORECASE):
                        findings.append(_make_finding(path, None, "config", key_alg, desc, sev, evidence=f"{key_path}: {val_str}", context=context))
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                walk(item, f"{parent_key}[{idx}]")

    walk(data)
    return findings


def _scan_binary(path: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        raw = Path(path).read_bytes()
    except Exception:
        return findings
    sample = raw[: 2 * 1024 * 1024]
    for needle, algorithm in [(b"RSA", "RSA"), (b"ECDSA", "ECDSA"), (b"BEGIN CERTIFICATE", "certificate")]:
        if needle.lower() in sample.lower():
            if algorithm == "certificate":
                findings.extend(_analyse_certificate(path))
                continue
            sev, desc = VULNERABLE_ALGORITHMS.get(algorithm, ("medium", f"Detected {algorithm}"))
            findings.append(
                _make_finding(path, None, "binary_signature", algorithm, desc, sev, evidence=f"binary marker {needle.decode('ascii')}", confidence="low", context={"migration_complexity": "high"})
            )
    return findings


def _analyse_certificate_bytes(raw: bytes, source: str, extra_context: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        cert = x509.load_der_x509_certificate(raw)
        public_key = cert.public_key()
        context = {"business_impact": "moderate", "migration_complexity": "medium"}
        context.update(extra_context or {})

        if isinstance(public_key, rsa.RSAPublicKey):
            key_size = public_key.key_size
            algorithm = "RSA-2048" if key_size <= 2048 else "RSA"
            sev, desc = VULNERABLE_ALGORITHMS.get(algorithm, VULNERABLE_ALGORITHMS["RSA"])
            findings.append(
                _make_finding(
                    source,
                    None,
                    "endpoint_certificate_public_key",
                    algorithm,
                    desc,
                    sev,
                    evidence=f"RSA public key {key_size} bits",
                    confidence="high",
                    context=context,
                )
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            sev, desc = VULNERABLE_ALGORITHMS["ECDSA"]
            findings.append(
                _make_finding(
                    source,
                    None,
                    "endpoint_certificate_public_key",
                    "ECDSA",
                    desc,
                    sev,
                    evidence=public_key.curve.name,
                    confidence="high",
                    context=context,
                )
            )

        signature_algorithm = cert.signature_algorithm_oid._name
        signature_upper = signature_algorithm.upper()
        if "ECDSA" in signature_upper:
            sev, desc = VULNERABLE_ALGORITHMS["certificate_signature: ECDSA"]
            findings.append(
                _make_finding(
                    source,
                    None,
                    "endpoint_certificate_signature",
                    "ECDSA",
                    desc,
                    sev,
                    evidence=signature_algorithm,
                    confidence="high",
                    context=context,
                )
            )
        if "SHA1" in signature_upper:
            sev, desc = VULNERABLE_ALGORITHMS["SHA1"]
            findings.append(
                _make_finding(
                    source,
                    None,
                    "endpoint_certificate_signature",
                    "SHA1",
                    desc,
                    sev,
                    evidence=signature_algorithm,
                    confidence="high",
                    context=context,
                )
            )
    except Exception:
        return findings
    return findings


def _parse_endpoint(endpoint: str) -> Tuple[str, int]:
    value = endpoint.strip().removeprefix("https://").split("/")[0]
    if not value:
        raise ValueError("empty endpoint")
    if value.startswith("[") and "]" in value:
        host, _, port_text = value[1:].partition("]:")
        return host, int(port_text or 443)
    host, sep, port_text = value.rpartition(":")
    if sep and port_text.isdigit():
        return host, int(port_text)
    return value, 443


def scan_endpoint(endpoint: str, timeout: float = 5.0) -> List[Dict[str, Any]]:
    """Scan a live TLS endpoint certificate and negotiated TLS settings."""
    host, port = _parse_endpoint(endpoint)
    source = f"endpoint://{host}:{port}"
    findings: List[Dict[str, Any]] = []
    context = {"business_impact": "moderate", "migration_complexity": "medium"}

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    if hasattr(ssl, "TLSVersion"):
        ssl_context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ssl_context.wrap_socket(sock, server_hostname=host) as tls:
            tls_version = tls.version() or "unknown"
            cipher = tls.cipher() or ("unknown", "unknown", 0)
            cert_raw = tls.getpeercert(binary_form=True)

    if tls_version in {"TLSv1", "TLSv1.0"}:
        sev, desc = VULNERABLE_ALGORITHMS["TLSv1.0"]
        findings.append(_make_finding(source, None, "endpoint_tls_version", "TLSv1.0", desc, sev, evidence=tls_version, confidence="high", context=context))
    elif tls_version == "TLSv1.1":
        sev, desc = VULNERABLE_ALGORITHMS["TLSv1.1"]
        findings.append(_make_finding(source, None, "endpoint_tls_version", "TLSv1.1", desc, sev, evidence=tls_version, confidence="high", context=context))

    cipher_name = str(cipher[0])
    if "RSA" in cipher_name and "ECDHE" not in cipher_name:
        sev, desc = VULNERABLE_ALGORITHMS["RSA"]
        findings.append(_make_finding(source, None, "endpoint_cipher", "RSA", desc, sev, evidence=cipher_name, confidence="medium", context=context))
    elif "ECDHE-RSA" in cipher_name:
        sev, desc = VULNERABLE_ALGORITHMS["tls_key_exchange: ECDHE-RSA"]
        findings.append(_make_finding(source, None, "endpoint_cipher", "ECDHE-RSA", desc, sev, evidence=cipher_name, confidence="medium", context=context))
    elif "ECDHE-ECDSA" in cipher_name:
        sev, desc = VULNERABLE_ALGORITHMS["ECDSA"]
        findings.append(_make_finding(source, None, "endpoint_cipher", "ECDSA", desc, sev, evidence=cipher_name, confidence="medium", context=context))

    if cert_raw:
        cert_findings = _analyse_certificate_bytes(cert_raw, source, context)
        for finding in cert_findings:
            finding["tls_version"] = tls_version
            finding["cipher"] = cipher_name
            finding["endpoint"] = f"{host}:{port}"
        findings.extend(cert_findings)

    for finding in findings:
        finding.setdefault("tls_version", tls_version)
        finding.setdefault("cipher", cipher_name)
        finding.setdefault("endpoint", f"{host}:{port}")
    return findings


def scan_endpoints(endpoints: Iterable[str], timeout: float = 5.0, max_workers: int = 6) -> List[Dict[str, Any]]:
    """Scan multiple live TLS endpoints concurrently."""
    endpoint_list = [endpoint.strip() for endpoint in endpoints if endpoint.strip()]
    all_findings: List[Dict[str, Any]] = []

    def scan_one(value: str) -> List[Dict[str, Any]]:
        try:
            return scan_endpoint(value, timeout=timeout)
        except Exception as exc:
            source = f"endpoint://{value.strip()}"
            return [
                _make_finding(
                    source,
                    None,
                    "endpoint_scan_error",
                    "TLS_SCAN_ERROR",
                    "Endpoint TLS scan failed",
                    "low",
                    evidence=str(exc),
                    confidence="high",
                    context={"business_impact": "low", "migration_complexity": "low"},
                )
            ]

    workers = max(1, min(max_workers, len(endpoint_list) or 1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        for result in executor.map(scan_one, endpoint_list):
            all_findings.extend(result)
    return sorted(all_findings, key=lambda item: item.get("risk_score", 0), reverse=True)


def _iter_candidate_files(path: str) -> Iterable[str]:
    ignored_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".pytest_cache"}
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in ignored_dirs]
        for fname in files:
            yield os.path.join(root, fname)


def _scan_one_file(filepath: str) -> List[Dict[str, Any]]:
    lower = os.path.basename(filepath).lower()
    suffix = Path(filepath).suffix.lower()
    try:
        size = os.path.getsize(filepath)
    except OSError:
        return []

    if size > 20 * 1024 * 1024:
        return []
    if suffix in CERT_EXTENSIONS:
        return _analyse_certificate(filepath)
    if suffix in CONFIG_EXTENSIONS:
        return _scan_yaml_json(filepath)
    if suffix in BINARY_EXTENSIONS:
        return _scan_binary(filepath)
    if suffix in TEXT_EXTENSIONS or lower in MANIFEST_NAMES or size <= 512 * 1024:
        return _scan_text_file(filepath)
    return []


def scan_repository(path: str, max_workers: Optional[int] = None) -> List[Dict[str, Any]]:
    """Recursively scan a repository directory for cryptographic risks."""
    files = list(_iter_candidate_files(path))
    all_findings: List[Dict[str, Any]] = []

    if len(files) > 1:
        workers = max_workers or min(8, (os.cpu_count() or 2) + 2)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            for result in executor.map(_scan_one_file, files):
                all_findings.extend(result)
    else:
        for filepath in files:
            all_findings.extend(_scan_one_file(filepath))

    seen = set()
    unique_findings = []
    for finding in all_findings:
        key = (
            finding.get("file"),
            finding.get("line_no"),
            finding.get("type"),
            finding.get("algorithm"),
            finding.get("evidence"),
        )
        if key not in seen:
            seen.add(key)
            unique_findings.append(finding)

    return sorted(unique_findings, key=lambda item: item.get("risk_score", 0), reverse=True)
