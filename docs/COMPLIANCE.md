# Sovereign Vault — Regulatory Compliance Mapping

**Framework Alignment for GDPR, HIPAA, and SOC 2 in LLM Architectures**  
*Document Version: 1.0.1*

---

## 1. General Data Protection Regulation (GDPR)

The European Union General Data Protection Regulation (EU Regulation 2016/679) imposes strict requirements on the collection, transmission, and processing of personal data. Sovereign Vault functions as an architectural privacy control providing cryptographic pseudonymization at the inference boundary.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    GDPR Article Alignment Matrix                            │
├─────────────────────┬───────────────────────────────────────────────────────┤
│ GDPR Article        │ Sovereign Vault Architectural Implementation          │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Article 4(5)        │ Cryptographic surrogate tokenization transforms raw   │
│ Pseudonymization    │ PII into opaque tokens; the reconstruction key and    │
│                     │ mapping store reside exclusively in local RAM.        │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Article 25          │ Data minimization by default; raw personal data is    │
│ Data Protection by  │ stripped prior to cloud egress, ensuring cloud LLMs   │
│ Design and Default  │ only ever process abstract entity representations.    │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Article 32          │ Cryptographic HMAC integrity verification, ephemeral  │
│ Security of         │ session isolation, and proactive random-byte memory   │
│ Processing          │ wiping upon session termination.                      │
└─────────────────────┴───────────────────────────────────────────────────────┘
```

### 1.1 Article 4(5) — Pseudonymization

Under GDPR Article 4(5), pseudonymization is defined as:
> *"the processing of personal data in such a manner that the personal data can no longer be attributed to a specific data subject without the use of additional information, provided that such additional information is kept separately and is subject to technical and organisational measures..."*

**Technical Implementation**:
- Sovereign Vault converts real-world personal data (e.g., names, email addresses, national identification numbers) into synthetic tokens formatted as `[[LABEL_UUID8_HMAC6]]`.
- The "additional information" required to reverse the pseudonymization (the mapping dictionary `self._store` and the 256-bit session secret `self._secret`) is held **exclusively in volatile local RAM** within the client organization's security boundary.
- The external cloud LLM provider processes only pseudonymized tokens. At no point does the external processor possess the cryptographic key or dictionary required to attribute tokens to living individuals.

### 1.2 Article 25 — Data Protection by Design and by Default

Article 25 mandates that controllers implement appropriate technical and organizational measures to ensure that, by default, only personal data necessary for each specific purpose of processing are processed.

**Technical Implementation**:
- By placing `VaultSession.tokenize()` at the ingestion stage of any external AI pipeline, data egress is minimized by default.
- Structural identifiers (SSNs, phone numbers, passport numbers, tax IDs) and contextual named entities are stripped before payload serialization.
- For workflows where cleartext output is not required (e.g., public benchmark evaluations, automated classification), `SealMode.SEALED` permanently disables the reconstruction mechanism, enforcing permanent pseudonymization.

### 1.3 Article 32 — Security of Processing

Article 32 requires controllers and processors to implement technical and organizational measures to ensure a level of security appropriate to the risk, including pseudonymization, encryption, and confidentiality resilience.

**Technical Implementation**:
- **Confidentiality**: Real values are isolated from the cloud provider, mitigating exposure from third-party model retraining, prompt caching, or vendor-side data breaches.
- **Integrity**: Every surrogate token is authenticated via HMAC-SHA256. Tampered, injected, or altered tokens trigger `VaultSealBreach` and halt pipeline execution.
- **Memory Sanitization**: Invoking `vault.destroy()` executes active memory overwriting—replacing plaintext strings with random hexadecimal bytes (`secrets.token_hex`) before dictionary deallocation—protecting against forensic heap inspection.

### 1.4 Cross-Border Data Transfers (Chapter V / Schrems II)

Under Chapter V of the GDPR and the CJEU *Schrems II* ruling, transferring personal data to third countries (such as the United States) requires supplementary technical measures when local surveillance laws conflict with EU privacy rights. Sovereign Vault provides a critical technical safeguard: by pseudonymizing data *prior* to cross-border API transmission, third-party cloud endpoints outside the EEA never receive direct personal data in cleartext.

---

## 2. Health Insurance Portability and Accountability Act (HIPAA)

Under the HIPAA Privacy Rule (45 CFR Part 160 and Part 164, Subparts A and E), covered entities and business associates must protect Protected Health Information (PHI). De-identification of health information can be achieved via two pathways: the **Safe Harbor Method** or the **Expert Determination Method**.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 HIPAA Safe Harbor 18 Identifiers Coverage                   │
├─────────────────────────────────────┬───────────────────────────────────────┤
│ Identifier Category (45 CFR §164)   │ Sovereign Vault Detection Tier        │
├─────────────────────────────────────┼───────────────────────────────────────┤
│ 1. Names                            │ Layer 2 (GLiNER: PERSON)              │
│ 2. Geographic subdivisions < state  │ Layer 2 (GLiNER: LOCATION, ADDRESS)   │
│ 3. Dates (except year)              │ Layer 2 (GLiNER: DATE_OF_BIRTH, date) │
│ 4. Telephone numbers                │ Layer 1 (Regex: PHONE)                │
│ 5. Fax numbers                      │ Layer 1 (Regex: PHONE)                │
│ 6. Email addresses                  │ Layer 1 (Regex: EMAIL)                │
│ 7. Social Security numbers          │ Layer 1 (Regex: SSN)                  │
│ 8. Medical Record numbers (MRN)     │ Layer 2 (GLiNER: MEDICAL_RECORD_NUM)  │
│ 9. Health plan beneficiary numbers  │ Layer 2 / Layer 3 (Ollama contextual) │
│ 10. Account numbers                 │ Layer 2 (GLiNER: FINANCIAL_ACCOUNT)   │
│ 11. Certificate / license numbers   │ Layer 1 (Regex: MICHIGAN_DL, etc.)    │
│ 12. Vehicle identifiers / serials   │ Layer 2 (GLiNER: VEHICLE_REG)         │
│ 13. Device identifiers & serials    │ Layer 3 (Ollama contextual sweep)     │
│ 14. Web URLs                        │ Layer 1 (Regex: URL patterns)         │
│ 15. IP addresses                    │ Layer 1 (Regex: IP_ADDRESS)           │
│ 16. Biometric identifiers           │ Layer 3 (Ollama contextual sweep)     │
│ 17. Full-face photographs           │ N/A (Text-only engine)                │
│ 18. Any unique identifying number   │ Layer 1-3 Ensemble + Entropy Check    │
└─────────────────────────────────────┴───────────────────────────────────────┘
```

### 2.1 Safe Harbor Method (§ 164.514(b)(2))

The Safe Harbor method requires the removal of 18 specific categories of identifiers concerning the individual, their relatives, employers, or household members:

1. **Layer 1 (Regex)** deterministically intercepts structural identifiers with mathematical certainty (confidence = 1.0): Social Security Numbers, domestic and international telephone numbers, email addresses, and IPv4 addresses.
2. **Layer 2 (GLiNER Transformer)** performs zero-shot entity extraction targeting person names, medical record numbers (`medical record number`), health-related organizations, geographic addresses, and dates of birth.
3. **Layer 3 (Ollama Local Sweep)** runs when entity counts fall below safety thresholds, capturing implicit health identifiers (e.g., *"the attending oncologist at St. Jude"*, specialized patient room assignments, device serial references).

### 2.2 Expert Determination Method (§ 164.514(b)(1))

Under the Expert Determination method, a person with appropriate knowledge and experience of statistical and scientific principles must determine that the risk is very small that the information could be used, alone or in combination with other reasonably available information, by an anticipated recipient to identify an individual.

Sovereign Vault supports expert determination through:
- **`vault.coverage_report()`**: Emits detailed per-layer entity distributions, active detection tiers, and confidence bucket metrics, providing statistical auditors with quantitative evidence of detection thoroughness.
- **Shannon Entropy Analysis**: Post-inference verification scans cloud responses for high-entropy strings ($H > 4.2$) that might indicate an identifier slipped past detection or was hallucinated by the model.
- **Referential Consistency**: Because tokens maintain consistent 1-to-1 surrogate mappings within a session, statistical distributions of clinical variables can be analyzed without exposing underlying identities.

---

## 3. Service Organization Control 2 (SOC 2)

Sovereign Vault aligns directly with the American Institute of Certified Public Accountants (AICPA) Trust Services Criteria (TSC) for Security, Confidentiality, and Privacy.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SOC 2 Trust Services Mapping                           │
├────────────────────┬──────────────────┬─────────────────────────────────────┤
│ Criteria Category  │ Trust Criteria   │ Sovereign Vault Architecture        │
├────────────────────┼──────────────────┼─────────────────────────────────────┤
│ Common Criteria /  │ CC6.1 (Logical   │ Session-scoped 256-bit keys ensure  │
│ Security           │ Access Control)  │ complete logical segregation between│
│                    │                  │ pipeline sessions in memory.        │
├────────────────────┼──────────────────┼─────────────────────────────────────┤
│ Common Criteria /  │ CC6.7 (Boundary  │ Pre-transmission tokenization acts  │
│ Security           │ Protection)      │ as a cryptographic egress firewall  │
│                    │                  │ for data traversing public APIs.    │
├────────────────────┼──────────────────┼─────────────────────────────────────┤
│ Confidentiality /  │ CC6.6 & CC7.2    │ audit_log() generates immutable     │
│ Monitoring         │ (Audit Logging)  │ operational telemetry without ever  │
│                    │                  │ writing raw PII into log sinks.     │
└────────────────────┴──────────────────┴─────────────────────────────────────┘
```

### 3.1 CC6.1 — Logical Access & Session Isolation

The entity restricts logical access to confidential information to authorized users and processes:
- Each `VaultSession` initializes an isolated 32-byte cryptographic secret via `secrets.token_bytes(32)`.
- Keys generated in Session A cannot be decoded, verified, or reconstructed by Session B.
- Module-level registry functions (`new_session`, `get_session`, `drop_session`) allow multi-tenant web servers (e.g., FastAPI middleware) to isolate concurrent pipeline requests safely.

### 3.2 CC6.7 — Boundary Protection & Data Transmission

The entity protects data transmission across external networks and third-party boundaries:
- Sovereign Vault enforces an internal egress boundary: cleartext PII is transformed into non-identifying surrogate tokens *before* reaching the outbound HTTP/TLS transport layer.
- Even in the event of an external TLS interception or third-party cloud logging breach, the compromised payload consists exclusively of opaque placeholder tokens.

### 3.3 CC6.6 & CC7.2 — Privacy-Preserving Audit Logging

Enterprise compliance requires maintaining an audit trail of all automated actions without violating privacy policies by logging sensitive identifiers:
- `vault.audit_log()` produces a comprehensive forensic audit record capturing entity classification labels, detection source layers, confidence scores, and span character boundaries:
  ```python
  [
      {
          "key": "[[SSN_D4E5F6A7_1c2d3e]]",
          "label": "SSN",
          "source_layer": "regex",
          "confidence": 1.0,
          "span_score": 1.1,
          "char_start": 8,
          "char_end": 19
      }
  ]
  ```
- **Zero Raw PII in Logs**: The `real_value` is strictly omitted from the audit trail, ensuring compliance with internal log retention and data residency rules.

---

## 4. Important Regulatory & Legal Disclaimers

> [!WARNING]
> **Sovereign Vault is a Technical Control, Not a Compliance Certification.**

Deploying Sovereign Vault does **not** automatically grant compliance with GDPR, HIPAA, SOC 2, CCPA, or any other global data protection standard. Organizations utilizing this software must account for the following legal realities:

1. **No Legal Advice**: This documentation and the Sovereign Vault software library do not constitute legal advice. Data protection regulations depend heavily on operational context, jurisdiction, data classification, and downstream processing activities.
2. **Independent Risk Assessments**: Organizations must conduct their own Data Protection Impact Assessments (DPIA), HIPAA risk analyses, and SOC 2 control reviews before deploying LLM pipelines into production.
3. **Business Associate Agreements (BAAs)**: Under HIPAA, using Sovereign Vault does not eliminate the necessity of entering into Business Associate Agreements (BAAs) with cloud model providers if protected health information remains present in residual or contextual form.
4. **Shared Responsibility Model**: Sovereign Vault provides client-side pseudonymization and reconstruction primitives. The deploying organization remains solely responsible for:
   - Ensuring host operating system and memory security.
   - Configuring appropriate model provider data retention and training policies.
   - Performing human-in-the-loop review of automated coverage reports (`coverage_report()`).
   - Establishing organizational data governance, access controls, and retention schedules.
