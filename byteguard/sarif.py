import hashlib
import json
from urllib.parse import quote

from .models import AnalysisReport, FileReport, Severity

SARIF_LEVELS = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}

def render_sarif(report: AnalysisReport) -> str:
    artifacts = []
    nodes: list[FileReport] = []
    rules = []
    rule_indexes: dict[str, int] = {}
    results = []
    notifications = []

    def visit(node: FileReport, parent: int | None = None):
        index = len(artifacts)
        nodes.append(node)
        normalized = node.name.replace("\\", "/")
        uri = (
            "file://"
            + quote(
                normalized if normalized.startswith("/") else "/" + normalized,
                safe="/:",
                errors="surrogatepass",
            )
            if parent is None
            else f"byteguard://payload/{index}"
        )
        artifact = {
            "location": {"uri": uri},
            "description": {"text": node.name},
            "length": node.size,
            "properties": {
                "format": node.kind,
                "complete": node.complete,
                "bytesScanned": node.bytes_scanned,
            },
        }
        if parent is not None:
            artifact["parentIndex"] = parent
        if node.hashes.get("sha256"):
            artifact["hashes"] = {"sha-256": node.hashes["sha256"]}
        artifacts.append(artifact)
        for child in node.children:
            visit(child, index)

    visit(report.root)
    for index, node in enumerate(nodes):
        location = {"uri": artifacts[index]["location"]["uri"], "index": index}
        for error in node.errors:
            notifications.append({"level": "warning", "message": {"text": f"{node.name}: {error}"}})
        for finding in node.findings:
            if finding.rule_id not in rule_indexes:
                rule_indexes[finding.rule_id] = len(rules)
                rules.append(
                    {
                        "id": finding.rule_id,
                        "shortDescription": {"text": finding.title},
                        "fullDescription": {"text": finding.description},
                        "properties": {
                            "precision": "medium",
                            "tags": ["security", "static-analysis"],
                        },
                    }
                )
            physical = {"artifactLocation": location}
            if finding.offset is not None:
                physical["region"] = {"byteOffset": finding.offset}
            identity = "\x00".join(
                (finding.rule_id, node.hashes.get("sha256", node.name), str(finding.offset))
            )
            results.append(
                {
                    "ruleId": finding.rule_id,
                    "ruleIndex": rule_indexes[finding.rule_id],
                    "level": SARIF_LEVELS[finding.severity],
                    "message": {"text": finding.title + ": " + finding.description},
                    "locations": [{"physicalLocation": physical}],
                    "partialFingerprints": {
                        "byteguard/v1": hashlib.sha256(
                            identity.encode("utf-8", errors="surrogatepass")
                        ).hexdigest()
                    },
                    "properties": {
                        "confidence": finding.confidence,
                        "severity": finding.severity.value,
                        "evidence": list(finding.evidence),
                    },
                }
            )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ByteGuard",
                        "version": report.engine_version,
                        "rules": rules,
                    }
                },
                "artifacts": artifacts,
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": report.complete,
                        "startTimeUtc": report.started_at,
                        "toolExecutionNotifications": notifications,
                        "properties": {
                            "coverageComplete": report.complete,
                            "establishesSafety": False,
                        },
                    }
                ],
                "properties": {
                    "risk": report.risk,
                    "heuristicScore": report.score,
                    "analysisType": "static_offline",
                    "establishesSafety": False,
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
