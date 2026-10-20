# PhishGuard — Explainable Phishing Email Risk Analyzer

> **Educational tool for the IBM Cybersecurity Fundamentals certification.**  
> PhishGuard is a local web application that analyses email content for common phishing indicators, assigns an indicative risk level, and explains the reasoning behind every finding.

---

## Table of Contents

1. [Quick Start](#1-quick-start)
2. [Project Structure](#2-project-structure)
3. [Architecture](#3-architecture)
4. [Detection Logic & Scoring](#4-detection-logic--scoring)
5. [Sample Emails](#5-sample-emails)
6. [Running the Tests](#6-running-the-tests)
7. [Test Results](#7-test-results)
8. [Limitations & Known False Positives / Negatives](#8-limitations--known-false-positives--negatives)
9. [Security & Privacy](#9-security--privacy)
10. [Remaining Future Improvements](#10-remaining-future-improvements)

---

## 1. Quick Start

### Prerequisites

- Python 3.10 or later
- pip

### Installation

```bash
# 1. Clone or download the project folder
cd PhishGuard

# 2. (Recommended) create a virtual environment
python3 -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

> `hypothesis` (in `requirements.txt`) is optional — it is only needed to run the property-based test class. The rest of the test suite runs without it.

### Running the application

```bash
streamlit run app.py
```

Streamlit will print a local URL (typically `http://localhost:8501`) and open it in your browser automatically.

The application works entirely offline once dependencies are installed. No API keys, accounts, or internet connection are required.

---

## 2. Project Structure

```
PhishGuard/
├── engine.py         # Detection engine — pure Python, no Streamlit dependency
├── app.py            # Streamlit UI — imports from engine.py
├── tests.py          # Test suite (unittest + optional hypothesis)
├── requirements.txt  # Python dependencies
└── README.md         # This file
```

The engine ([`engine.py`](engine.py)) is a standalone pure-Python module with no Streamlit dependency. This means [`tests.py`](tests.py) can import and test it directly with `from engine import ...` — no browser or Streamlit server required.

---

## 3. Architecture

```
User Input
  ├── Sender address  ("Display Name <addr>" format supported)
  ├── Subject line
  ├── Email body      (plain text or HTML — tags stripped before analysis)
  └── .eml file upload (single or bulk — parsed via Python stdlib email module)
          │
          ▼
  ┌─────────────────────────┐
  │  Pre-processing          │  HTML strip · display-name parse · leet normalise
  └────────┬────────────────┘
           │
           ▼
  ┌───────────────────────────────────────────────────────┐
  │                   Detection Engine                    │
  │                                                       │
  │  Rule 1 — Urgency / Fear Language      (≤ 20 pts)    │
  │  Rule 2 — Credential / Payment Request (≤ 25 pts)    │
  │  Rule 3 — Suspicious URL Pattern       (  20 pts)    │
  │  Rule 4 — Sender Inconsistency         (  20 pts)    │
  │  Rule 5 — Sensitive PII Request        (≤ 15 pts)    │
  │  Rule 6 — Anchor Text / Href Mismatch  (≤ 15 pts)    │
  │                                                       │
  │  Co-occurrence bonus: +10 pts when 3+ rules fire     │
  └───────────────────────────────────────────────────────┘
           │
           ▼
  ┌──────────────────────────────┐
  │        Risk Scorer           │
  │  Low: 0–29  Medium: 30–59   │
  │  High: 60–100  (capped)     │
  └──────────────────────────────┘
           │
           ▼
  Results panel + indicator cards + weight chart + CSV export
  Header warnings panel (.eml mode)
  Session dashboard (counters, history table, distribution chart)
  Bulk results table + batch CSV download
```

The UI layer ([`app.py`](app.py)) is a thin Streamlit wrapper around the engine. Three input tabs are available:

| Tab | Description |
|---|---|
| ✏️ Manual Entry | Type or paste sender, subject, and body directly; load from sample emails |
| 📎 Upload .eml File | Upload a raw RFC 5322 `.eml` file; fields extracted automatically; header analysis included |
| 📂 Bulk Upload | Upload multiple `.eml` files at once; get a summary table and batch CSV download |

---

## 4. Detection Logic & Scoring

### Pre-processing

Before any rule runs, three transformations are applied:

| Step | Function | Purpose |
|---|---|---|
| HTML stripping | `_strip_html()` | Removes `<tags>` and decodes HTML entities to prevent keyword-hiding evasion |
| Display-name parsing | `_extract_address()` | Extracts the real address from `"Name" <addr@domain>` format |
| Leet normalisation | `_normalise_leet()` | Maps `paypa1` → `paypal`, `g00gle` → `google` for brand-name matching |

---

### Rule 1 — Urgency / Fear Language

**Weight:** 10 pts (1 match) · 15 pts (2 matches) · 20 pts (3+ matches)

**Rationale:** Social engineering relies on artificial time pressure to prevent victims from thinking critically. Scaling the weight by match density reduces false positives from emails that coincidentally contain a single common word like "expires".

**Patterns include:** `urgent`, `immediately`, `act now`, `account suspended`, `unusual activity`, `final notice`, `action required`, `time-sensitive`, `within N hours`, and more.

---

### Rule 2 — Credential / Payment Request

**Weight:** 15 pts (1–2 matches) · 25 pts (3+ matches)

**Rationale:** Only explicit verb+noun action phrases are matched (e.g. "enter your password", "provide your card number") to avoid false positives on legitimate password-reset notification emails.

**Patterns include:** `enter your password`, `verify your credentials`, `confirm your account details`, `credit card`, `CVV`, `card number`, `expiry date`, and more.

---

### Rule 3 — Suspicious URL Pattern

**Weight:** 20 pts (any hit)

**Rationale:** Scans both subject and body. URLs are never fetched or resolved — text-only inspection.

**Checks:** Raw IP-address host · 12 known URL shorteners (bit.ly, tinyurl.com, cutt.ly…) · digit-substituted lookalike domains.

---

### Rule 4 — Sender Inconsistency

**Weight:** 20 pts (any hit)

**Three sub-checks:**
1. Display-name spoof — `"PayPal Support" <attacker@evil.com>`
2. Lookalike domain with leet normalisation — `paypa1-support.com`
3. Free-provider impersonation — Gmail/Yahoo + brand mention in content

**Brand list (24 entries):** PayPal, Amazon, Apple, Microsoft, Google, Netflix, Facebook, Instagram, Twitter, LinkedIn, Dropbox, Chase, Bank of America, Wells Fargo, Citibank, Barclays, HSBC, FedEx, UPS, DHL, USPS, IRS, HMRC.

---

### Rule 5 — Sensitive PII Request

**Weight:** 10 pts (1 match) · 15 pts (2+ matches)

**Rationale:** Requests for government ID numbers, bank account details, or biographic information indicate identity-fraud intent.

**Patterns include:** `social security`, `SSN`, `date of birth`, `bank account`, `routing number`, `passport`, `driver's license`, `national id`, `medical record`, and more.

---

### Rule 6 — Anchor Text / Href Mismatch *(new)*

**Weight:** 10 pts (1 mismatch) · 15 pts (2+ mismatches)

**Rationale:** A classic HTML phishing technique — the link text shows a trusted URL (e.g. `https://www.paypal.com`) while the `href` points to a malicious host. Detected using Python's stdlib `html.parser`.

---

### .eml Header Analysis *(informational — no score impact)*

When an `.eml` file is uploaded, the following header fields are inspected and warnings shown separately in the UI:

- **Reply-To ≠ From** — replies would go to a different mailbox
- **Received-SPF: fail / softfail** — sending server not authorised for this domain
- **DKIM signature fail** — message may have been tampered with
- **DMARC fail** — message does not align with the domain's authentication policy
- **Return-Path domain ≠ From domain** — bounce messages go to a different domain

Header warnings are informational only. They require DNS validation to be definitive, which is not available locally.

---

### Co-occurrence Bonus

**+10 pts** when 3 or more distinct rules fire simultaneously. Reflects the compounding probability when multiple independent signals appear in one email.

---

### Scoring Thresholds

| Risk Level | Score Range | Interpretation |
|---|---|---|
| 🟢 Low | 0 – 29 | No strong indicators found |
| 🟡 Medium | 30 – 59 | Some suspicious elements present |
| 🔴 High | 60 – 100 | Multiple strong indicators detected |

Scores are additive and capped at 100. No single indicator is treated as definitive proof of phishing.

---

## 5. Sample Emails

Five fictional demonstration emails are bundled with the application:

| Sample | Sender | Expected Risk | Primary Indicators |
|---|---|---|---|
| A — Credential Harvest | `security-alert@paypa1-support.com` | 🔴 High | Urgency, credential request, IP-address URL, sender inconsistency, bonus |
| B — Suspicious Link | `newsletter@shop-deals.net` | 🟡 Medium | Urgency, URL shortener |
| C — Internal Email | `hr@acmecorp.com` | 🟢 Low | None |
| D — Display-Name Spoof | `"FedEx Delivery" <noreply@parcel-track99.ru>` | 🔴 High | Display-name spoof, PII request, URL shortener |
| E — Anchor Text Mismatch | `noreply@secure-paypal-alert.com` | 🔴 High | Sender inconsistency, urgency, anchor text mismatch |

---

## 6. Running the Tests

```bash
python3 tests.py
```

No external packages are required for the core suite. The test file imports directly from `engine.py` using `from engine import ...`. Tests run in under a second with no browser or server.

To also run the property-based tests:

```bash
pip install hypothesis
python3 tests.py
```

---

## 7. Test Results

**88 tests — 87 pass, 1 skipped** (the skip is the property-based class when `hypothesis` is not installed).

| Class | Tests | Coverage |
|---|---|---|
| `TestHTMLStripper` | 4 | Tag removal, entity decoding, evasion resistance |
| `TestAnchorExtractor` | 4 | Anchor/href extraction from HTML |
| `TestDisplayNameParser` | 4 | Angle-bracket address extraction |
| `TestLeetNormaliser` | 4 | All 9 digit-to-letter mappings |
| `TestUrgencyRule` | 7 | Proportional weight, HTML evasion, new patterns |
| `TestCredentialRule` | 7 | Tightened patterns, bare-word false-positive prevention |
| `TestSuspiciousURLRule` | 7 | IP, shorteners, lookalike, subject-line scanning |
| `TestSenderInconsistencyRule` | 7 | Display-name spoof, lookalike domain, expanded brands |
| `TestSensitiveInfoRule` | 4 | Proportional weight, `national id` pattern |
| `TestAnchorMismatchRule` | 6 | Mismatch detection, weight scaling, Sample E |
| `TestEmlParser` | 9 | Body extraction, Reply-To, SPF, DKIM, DMARC, Return-Path |
| `TestAnalyzeEmail` | 11 | End-to-end samples, score cap, co-occurrence bonus, Rule 6 |
| `TestValidateInputs` | 8 | Display-name format, length limits, multiple errors |
| `TestCSVReport` | 5 | Score, risk level, indicator names, bonus row, valid CSV |
| `TestPropertyBased` | 5 | Score bounds, no-crash for arbitrary input (requires hypothesis) |

Current sample scores:

| Sample | Score | Risk Level |
|---|---|---|
| A — Credential Harvest | 85 / 100 | 🔴 High |
| B — Suspicious Link | 30 / 100 | 🟡 Medium |
| C — Internal Email | 0 / 100 | 🟢 Low |
| D — Display-Name Spoof | ≥ 55 / 100 | 🟡–🔴 |
| E — Anchor Text Mismatch | ≥ 40 / 100 | 🟡–🔴 |

---

## 8. Limitations & Known False Positives / Negatives

### False positives (legitimate emails flagged as suspicious)

- **Urgency rule:** transactional emails (e.g. "Your subscription expires in 3 days") trigger Rule 1 at a low weight.
- **Credential rule:** a legitimate service announcing "We've updated our card details process" could match payment-card patterns.
- **Sender rule:** a small business emailing from Gmail while mentioning a major brand will be flagged for free-provider impersonation.
- **PII rule:** a medical practice referencing "medical records" in a routine appointment reminder will score 10 pts.
- **Anchor mismatch rule:** HTML emails that use a URL as link text but redirect through a tracking proxy (common in legitimate marketing emails) may be flagged.

### False negatives (phishing emails that score Low)

- **Novel tactics:** vishing bait, QR-code-only phishing, or social engineering without keywords scores 0.
- **Non-English phishing:** all patterns are English-only.
- **Real-word lookalike domains:** `paypal-security.com` (no digit substitution) is not flagged by the domain rule alone.
- **Indirect credential harvesting:** advanced campaigns containing only a single benign-looking link with no suspicious keywords.

### General limitations

- Rule weights and thresholds are hand-tuned heuristics, not statistically derived from labelled data.
- Header analysis (SPF/DKIM/DMARC) is informational only — definitive conclusions require DNS validation, which is not available in a local offline tool.
- This tool is not suitable for automated filtering of real email traffic and does not constitute production-grade security software.

---

## 9. Security & Privacy

| Guarantee | Implementation |
|---|---|
| No data stored | Email content held in Python variables and in-memory session state only. Nothing written to disk. |
| No data transmitted | Zero outbound network requests. Works fully offline after `pip install`. |
| URLs never visited | URL detection is purely textual — no HTTP requests are made to links found in emails. |
| No logging | No email fields are written to any log file. |
| Local only | Streamlit binds to `localhost` by default — not accessible from other machines. |
| Session reset | All session history cleared when the browser tab is refreshed or closed. |
| .eml files | Parsed in memory only — the file object is discarded immediately after analysis. |

---

## 10. Remaining Future Improvements

The following items were assessed but are out of scope for this submission:

| Area | Improvement |
|---|---|
| Detection | Multi-language urgency and credential patterns |
| Scoring | Derive weights statistically from a labelled dataset (e.g. Enron + PhishTank) |
| UI | Side-by-side comparison of two emails |
| Export | PDF report generation per analysis |
