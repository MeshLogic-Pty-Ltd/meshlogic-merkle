# Security Policy

MeshLogic Pty Ltd takes the security of our software seriously. This document describes how to report a vulnerability in `meshlogic-merkle` and what to expect.

This page is MeshLogic's public vulnerability-disclosure policy. The full internal process is available to customers on request via `security@meshlogic.ai`.

---

## Reporting a Vulnerability

**Email `security@meshlogic.ai`** with:

- a description of the issue;
- steps to reproduce;
- the affected component(s) and version(s), if known;
- your CVSS v3.1 estimate, if you have one;
- whether you would like to be credited publicly.

Please do not open a public issue or pull request for a suspected vulnerability.

We acknowledge **all** reports. SLAs:

| Severity                  | Acknowledge | Triage complete | Fix deployed |
| ------------------------- | ----------- | --------------- | ------------ |
| **Critical (CVSS 9.0+)**  | 24h         | 48h             | 7 days       |
| **High (CVSS 7.0–8.9)**   | 72h         | 7 days          | 30 days      |
| **Medium (CVSS 4.0–6.9)** | 7 days      | 14 days         | 90 days      |
| **Low (CVSS 0.1–3.9)**    | 14 days     | 30 days         | 180 days     |

---

## Safe Harbor

MeshLogic supports good-faith security research. We will not pursue legal action against researchers who:

1. make a good-faith effort to avoid privacy violations, destruction of data and service interruption;
2. access only the minimum data necessary to demonstrate the vulnerability;
3. give MeshLogic reasonable time (90 days by default) to address the issue before public disclosure;
4. do not exploit the vulnerability beyond what is necessary to confirm it exists.

---

## Out of Scope

Please do **not** report:

- **DoS or volumetric testing** against any MeshLogic-operated service;
- **social engineering** of MeshLogic personnel;
- **physical attacks** against MeshLogic facilities or personnel;
- issues in **third-party SaaS** we use but do not operate (report those to the vendor);
- issues in **customer-controlled tenants** without that customer's explicit written authorisation.

---

## Recognition

With your permission, researchers acting in good faith are credited in the published advisory. MeshLogic does not currently offer a monetary bug bounty.

---

## Disclosure Timeline

MeshLogic follows a **90-day coordinated-disclosure default**:

- **Day 0:** report received and acknowledged within SLA;
- **Days 0–30:** triage; fix developed and tested;
- **Days 30–90:** coordinated-disclosure window; patch deployed; advisory drafted;
- **Day 90:** advisory published, CVE assigned if applicable, affected customers notified;
- **Extension:** up to 14 more days may be agreed in writing for genuinely complex fixes.

---

## Contact

- `security@meshlogic.ai`
- [security.txt (RFC 9116)](https://meshlogic.ai/.well-known/security.txt)
