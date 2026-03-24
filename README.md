# RiskLayer - The decision layer for security findings.


## Beschreibung des Vorhabens

Ziel des Vorhabens ist der Aufbau einer erweiterten Security-Pipeline in GitLab CI/CD, die Container-Images, SBOMs und CVE-Findings automatisiert verarbeitet und dabei über einen reinen Severity-basierten Scan hinausgeht. Die Pipeline soll nicht nur bekannte Schwachstellen melden, sondern deren betriebliche Relevanz im konkreten Anwendungskontext bewerten und daraus belastbare Folgeaktionen ableiten.

Ausgangspunkt ist eine klassische Security-Pipeline, in der ein Container-Image gebaut, eine Software Bill of Materials erzeugt und anschließend ein CVE-Scan durchgeführt wird. Dieser Teil bleibt bewusst deterministisch und basiert auf etablierten Werkzeugen. Ein typischer Grundaufbau kann dabei wie folgt aussehen:

```yaml
stages:
  - build
  - security
  - evaluate

variables:
  IMAGE_NAME: "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA"
  SBOM_FILE: "sbom.spdx.json"
  CVE_REPORT_FILE: "trivy-report.json"

build_image:
  stage: build
  image: gcr.io/kaniko-project/executor:latest
  script:
    - /kaniko/executor
      --context "${CI_PROJECT_DIR}"
      --dockerfile "${CI_PROJECT_DIR}/Dockerfile"
      --destination "${IMAGE_NAME}"

generate_sbom:
  stage: security
  image: anchore/syft:latest
  script:
    - syft "${IMAGE_NAME}" -o spdx-json > "${SBOM_FILE}"
  artifacts:
    paths:
      - "${SBOM_FILE}"

scan_image:
  stage: security
  image: aquasec/trivy:latest
  script:
    - trivy image --format json --output "${CVE_REPORT_FILE}" "${IMAGE_NAME}"
  artifacts:
    paths:
      - "${CVE_REPORT_FILE}"
```

Dieser klassische Teil liefert die technischen Rohdaten: das gebaute Image, die SBOM und den Schwachstellenbericht. Für den operativen Betrieb reicht diese Rohdatenerzeugung jedoch nur begrenzt aus. Ein High- oder Critical-Finding zeigt zunächst nur, dass ein bekanntes Problem in einem Paket vorhanden ist. Daraus ergibt sich noch keine belastbare Aussage darüber, ob das Paket im Runtime-Pfad relevant ist, ob ein Fix verfügbar ist, ob der betroffene Service internetexponiert ist oder ob es sich um eine Build-Time-Dependency ohne unmittelbare Laufzeitrelevanz handelt.

An dieser Stelle wird die Pipeline um einen spezialisierten Analyse-Layer erweitert. Dieser Analyse-Layer folgt einem agentischen Ansatz. Er verarbeitet nicht nur die Ergebnisse des Scans, sondern wertet sie in Verbindung mit weiteren Kontextinformationen aus. Ziel ist ein strukturierter Entscheidungsdatensatz, der zwischen Blocker, Warnung, Ausnahme und dokumentierter Nachverfolgung unterscheiden kann.

Ein erster technischer Zuschnitt dieses Analyse-Layers kann als eigener Evaluierungsjob in der Pipeline umgesetzt werden:

```yaml
evaluate_findings:
  stage: evaluate
  image: python:3.12-slim
  needs:
    - scan_image
    - generate_sbom
  variables:
    ENVIRONMENT_RISK: "prod"
    INTERNET_EXPOSED: "true"
  script:
    - python ci/evaluate_findings.py "${CVE_REPORT_FILE}" "${SBOM_FILE}"
  artifacts:
    paths:
      - evaluation-result.json
```

Der Evaluator übernimmt damit die Rolle einer steuernden Zwischenschicht. Er erzeugt keine weiteren Findings, sondern bewertet vorhandene Findings entlang zusätzlicher Kriterien. Ein minimalistischer Einstieg könnte in Python beispielsweise so aussehen:

```python
import json
import sys
from pathlib import Path

cve_report_file = sys.argv[1]
sbom_file = sys.argv[2]

with open(cve_report_file, "r", encoding="utf-8") as f:
    report = json.load(f)

results = report.get("Results", [])
critical = []
high = []

for result in results:
    for vuln in result.get("Vulnerabilities", []):
        entry = {
            "package": vuln.get("PkgName"),
            "installed_version": vuln.get("InstalledVersion"),
            "fixed_version": vuln.get("FixedVersion"),
            "severity": vuln.get("Severity"),
            "cve": vuln.get("VulnerabilityID"),
        }

        if vuln.get("Severity") == "CRITICAL":
            critical.append(entry)
        elif vuln.get("Severity") == "HIGH":
            high.append(entry)

decision = "pass"
reason = []

if any(v.get("fixed_version") for v in critical):
    decision = "fail"
    reason.append("Critical vulnerabilities with available fixes detected.")
elif critical:
    decision = "warn"
    reason.append("Critical vulnerabilities detected, but no direct fix is available.")
elif len(high) >= 5:
    decision = "warn"
    reason.append("Multiple high severity vulnerabilities detected.")

output = {
    "decision": decision,
    "reasons": reason,
    "summary": {
        "critical": len(critical),
        "high": len(high)
    },
    "critical_findings": critical,
    "high_findings": high
}

Path("evaluation-result.json").write_text(
    json.dumps(output, indent=2),
    encoding="utf-8"
)

print(json.dumps(output, indent=2))

if decision == "fail":
    sys.exit(1)
```

Dieser erste Evaluator arbeitet noch regelbasiert, bildet aber bereits die fachliche Intention des Vorhabens ab: Er trennt den reinen Scan von der eigentlichen Entscheidung. Genau diese Trennung ist zentral. Der Security-Scanner liefert technische Evidenz, der Evaluator erzeugt daraus eine Einordnung im Nutzungskontext.

Im weiteren Ausbau soll dieser Evaluator nicht auf einfache If-Else-Logik beschränkt bleiben, sondern um einen spezialisierten Security-Agenten ergänzt werden. Dieser Agent ist kein allgemeiner Chatbot, sondern ein eng fokussierter Analysebaustein, der CVE-Findings, SBOM-Daten, Paketdateien und projektbezogene Metadaten verarbeitet. Dazu gehören etwa `pom.xml`, `package.json`, `requirements.txt`, das Dockerfile oder definierte Risikoattribute der Zielumgebung. Die Eingabedaten können in einem strukturierten Kontextobjekt gebündelt werden:

```json
{
  "environment": "prod",
  "internet_exposed": true,
  "service_type": "backend-api",
  "runtime_language": "java",
  "findings": [
    {
      "cve": "CVE-2026-12345",
      "package": "openssl",
      "severity": "CRITICAL",
      "fixed_version": "3.0.15"
    }
  ],
  "exceptions": [],
  "repo_files": [
    "Dockerfile",
    "pom.xml"
  ]
}
```

Auf dieser Grundlage soll der Agent eine differenzierte Bewertung erzeugen, beispielsweise in einer Form wie dieser:

```json
{
  "decision": "warn",
  "confidence": "high",
  "reasoning": [
    "Critical CVE detected in package openssl.",
    "Affected package is present in the runtime image.",
    "Service is internet exposed.",
    "Fix is available, but update requires base image change."
  ],
  "recommended_action": "create_issue",
  "owner": "platform-team"
}
```

Damit wird die Pipeline von einem rein meldenden Mechanismus zu einer steuernden Entscheidungsschicht weiterentwickelt. Das Ergebnis des Agenten kann anschließend durch einen Policy-Layer technisch weiterverarbeitet werden. Dieser Policy-Layer muss nicht identisch mit dem Agenten sein. Er kann bewusst hart und deterministisch formuliert werden, um Governance-Regeln revisionsfähig durchzusetzen. Hier bietet sich eine OPA-basierte Prüfung an, etwa in einer Form wie dieser:

```rego
package security.cve

default allow = false

deny[msg] {
  input.decision == "fail"
  msg := "Pipeline blocked due to critical vulnerabilities with available fix."
}

warn[msg] {
  input.decision == "warn"
  msg := "Security findings require manual review."
}

allow {
  input.decision == "pass"
}
```

Die technische Auswertung dieser Policy kann dann als weiterer Pipeline-Schritt erfolgen:

```yaml
policy_gate:
  stage: evaluate
  image: openpolicyagent/opa:latest
  needs:
    - evaluate_findings
  script:
    - opa eval --format pretty --input evaluation-result.json --data policy/security.rego "data.security.cve"
```

Der Nutzen dieser Aufteilung liegt in der klaren Rollentrennung. Der spezialisierte Agent bewertet Relevanz, Kontext und mögliche Maßnahmen. Der Policy-Layer setzt harte organisatorische Regeln durch. Dadurch bleibt das System nachvollziehbar, kontrollierbar und auditierbar, ohne auf reine Severity-Schwellenwerte reduziert zu sein.

Zusätzlich kann die Pipeline um automatische Folgeaktionen ergänzt werden. Bei Findings mittlerer Priorität soll beispielsweise kein Deployment blockiert, aber ein GitLab-Issue erzeugt werden. Auch dieser Teil bleibt bewusst einfach und verwendet keinen schwergewichtigen Spezialmechanismus, sondern einen kleinen API-Job:

```yaml
create_security_issue:
  stage: evaluate
  image: curlimages/curl:latest
  needs:
    - evaluate_findings
  script:
    - |
      DECISION=$(sed -n 's/.*"decision": "\(.*\)".*/\1/p' evaluation-result.json | head -1)
      if [ "$DECISION" = "warn" ] || [ "$DECISION" = "fail" ]; then
        curl --request POST \
          --header "PRIVATE-TOKEN: $GITLAB_API_TOKEN" \
          --data-urlencode "title=Security findings in pipeline $CI_PIPELINE_ID" \
          --data-urlencode "description=See evaluation-result.json and scan artifacts for details." \
          "$CI_API_V4_URL/projects/$CI_PROJECT_ID/issues"
      fi
```

Perspektivisch soll das Vorhaben zudem über reine OS- und Base-Image-CVEs hinaus erweitert werden. Für Applikationsabhängigkeiten kann ergänzend ein weiterer Analysepfad aufgebaut werden, der neben klassischen CVEs auch strukturelle Risiken in Dependency-Ketten berücksichtigt. Dazu zählen etwa verwaiste Bibliotheken, ungewöhnliche Release-Muster, fragile Maintainer-Strukturen oder riskante transitive Abhängigkeiten. Ein solcher Pfad ergänzt die Container-Security um eine Supply-Chain-Perspektive und kann zusätzliche Signale für den Agenten und den Policy-Layer liefern.

Ein möglicher zusätzlicher GitLab-Job dafür könnte so aussehen:

```yaml
depscope_scan:
  stage: security
  image: depscope/depscope
  script:
    - depscope scan . --profile enterprise --output json > depscope-report.json
  artifacts:
    paths:
      - depscope-report.json
```

Die Gesamtlösung zielt damit auf eine Security-Pipeline, die technische Findings in operative Entscheidungen überführt. Der Mehrwert liegt nicht in einem weiteren Scanner, sondern in einer zusätzlichen Auswertungsschicht zwischen Scan-Ergebnis und Handlung. Diese Schicht reduziert manuelle Nachbewertung, erhöht die Signalqualität, priorisiert Maßnahmen anhand des tatsächlichen Kontexts und schafft eine Grundlage für nachvollziehbare automatisierte Reaktionen im Delivery-Prozess.

## Kurzform als Zielbild

Das Vorhaben etabliert eine GitLab-basierte Security-Pipeline mit drei klar getrennten Ebenen:

```text
Container Build / SBOM / CVE Scan
→ spezialisierter Analyse-Agent für Kontextbewertung
→ Policy-Gate für harte Governance-Entscheidungen
→ Folgeaktionen wie Fail, Warnung, Issue oder Merge Request
```



# Alexander Gottschlich // Elastic2ls

[Website](https://www.elastic2ls.com/)

[Contact](info@elastic2ls.com)

[License](https://github.com/AlexanderGottschlich/.github/blob/main/LICENSE)
