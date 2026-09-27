# Compliance mappings

What `guardlayer evidence export` maps each audited decision to. Generated from `guardlayer.compliance`; see
[Audit log and evidence](../concepts/audit-and-evidence.md) for how to use it.

<!-- gen:compliance -->

CSA AI Controls Matrix control IDs and titles are referenced from the Cloud Security Alliance AI Controls Matrix Version
1.1.1 (© Cloud Security Alliance, all rights reserved); no control text is reproduced. Verified against CSA's official
spreadsheet on 2026-09-27. MITRE ATLAS mitigation names are from MITRE's atlas-data release v2026.09 (Apache-2.0). OWASP
AISVS 1.0 (CC BY-SA 4.0, OWASP Foundation) requirements have no titles: the descriptions here are GuardLayer's own
summaries; cite a requirement as `v1.0-C<id>`. The UK Code of Practice for the Cyber Security of AI (DSIT and NCSC, January 2025) is
Crown copyright, used under the [Open Government Licence v3.0](https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/);
provision numbers as published on gov.uk, descriptions GuardLayer's own. ETSI EN 304 223 V2.1.1 (2025-12), the European
Standard that supersedes ETSI TS 104 223, is © ETSI with all rights reserved: GuardLayer references provision numbers only
(checked against ETSI's official PDF), with its own descriptions. NIST SP 800-53 Rev. 5.2.0 is a US government work in the
public domain; titles from NIST's OSCAL catalog. NIST CSF 2.0 (public domain): subcategory text from NIST's CSF 2.0
reference export; each CSF subcategory used is consistent with the SP 800-53 families NIST relates it to. ISO/IEC 42001 and ISO/IEC 27001 (© ISO) are referenced by
control number and short title only. SOC 2 Trust Services Criteria (© AICPA) are referenced by criterion ID, checked against
the 2022 revised edition; descriptions are GuardLayer's own.
The HIPAA Security Rule (45 CFR Part 164 Subpart C) is US federal regulation; citations checked against the eCFR as of
2026-09-24 (the rule in force; HHS's January 2025 proposed update is not final). It applies only where the AI system
handles electronic protected health information, and GuardLayer detects common personal identifiers, not health data.
GDPR (Regulation (EU) 2016/679) mappings apply only where personal data is involved; article numbers and titles per the
official text on EUR-Lex. GuardLayer's personal-data detection covers common identifiers, not every category of personal data.
PCI DSS v4.0.1 (© PCI Security Standards Council) is referenced by requirement number, checked against the Council's
published Summary of Changes and practitioner references; descriptions are GuardLayer's own. 10.3.4 expects alerts on
log changes: run `guardlayer audit verify` on a schedule with alerting. 3.5.1 isn't claimed: the audit log's hash of the
scanned text is unkeyed, and PCI DSS requires keyed hashes for card numbers at rest.
CMMC 2.0 Level 2 practice IDs and titles are from the DoD's CMMC Assessment Guide Level 2 v2.13 (September 2024), which
follows NIST SP 800-171 Rev. 2 (public domain). FedRAMP 20x Key Security Indicators are from FedRAMP's Consolidated Rules
(version 2026.09.13.02); FedRAMP Rev. 5 authorisations use NIST SP 800-53 controls, so use the `nist-sp-800-53` evidence.
NIS2: Directive (EU) 2022/2555 Article 21(2) and the annex of Commission Implementing Regulation (EU) 2024/2690 (numbers as
in ENISA's Technical Implementation Guidance v1.0); the annex binds only the entity types it lists (for example cloud,
data-centre and managed service providers).
