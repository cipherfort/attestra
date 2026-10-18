// SPDX-License-Identifier: Apache-2.0
// Readable names for evidence types (config/evidence-types.yaml). Unknown types show their id.
const LABELS: Record<string, string> = {
  "registry.application": "Application record",
  "registry.classification": "Classification decision",
  "repo.ruleset": "Branch protection",
  "repo.security_settings": "Repository security settings",
  "repo.codeowners": "Code owners",
  "repo.access": "Repository access",
  "repo.actions_policy": "Actions policy",
  "repo.environments": "Deployment environments",
  "repo.threat_model": "Threat model (in the repository)",
  "scan.workflow_hardening": "Workflow hardening scan",
  "scan.sast": "Static analysis",
  "scan.sca": "Dependency scan",
  "scan.secrets": "Secrets scan",
  "scan.iac": "Infrastructure-as-code scan",
  "scan.container": "Container image scan",
  "scan.licence": "Licence check",
  "scan.malicious_package": "Malicious package check",
  "scan.dast": "Dynamic application scan",
  "scan.api": "API security scan",
  sbom: "Software bill of materials",
  "sbom.eol": "End-of-life check",
  "provenance.attestation": "Build provenance",
  "test.security": "Security tests",
  "deploy.record": "Deployment verification",
  "assessment.threat_model": "Threat model review",
  "assessment.architecture_review": "Architecture review",
  "assessment.pentest": "Penetration test",
  "assessment.manual_control": "Manual control assessment",
  "assessment.samm_interview": "SAMM interview",
  "training.completion": "Training completion",
  "cloud.posture": "Cloud posture",
  "siem.log_source_health": "SIEM log source health",
  "vuln.posture": "Vulnerability posture",
  "process.review_record": "Process review",
};

export function evidenceLabel(type: string | null | undefined): string {
  return type ? (LABELS[type] ?? type) : "Evidence";
}
