# =============================================================================
# PhishGuard — Detection Engine
# Pure Python module — no Streamlit dependency.
# Import this from app.py and from tests.py.
# =============================================================================
# IMPORTANT NOTICE
# This tool is for educational purposes only.
# It may produce false positives and false negatives.
# It does not replace professional email security software.
# No submitted email content is stored, logged, or transmitted.
# =============================================================================

import re
import io
import csv
import email          # stdlib — parses raw .eml files
import email.policy
from email import policy as email_policy
from html.parser import HTMLParser

# =============================================================================
# PRE-PROCESSING HELPERS
# =============================================================================

# ---------------------------------------------------------------------------
# HTML stripping
# Removes tags and decodes common HTML entities so that keywords hidden as
# <b>URGENT</b> or &#85;RGENT are exposed before rules run.
# ---------------------------------------------------------------------------
_HTML_TAG_RE    = re.compile(r"<[^>]+>", re.IGNORECASE)
_HTML_ENTITY_RE = re.compile(r"&[a-z]+;|&#\d+;", re.IGNORECASE)

def _strip_html(text: str) -> str:
    """Remove HTML tags and decode common named/numeric HTML entities."""
    text = _HTML_TAG_RE.sub(" ", text)
    entity_map = {
        "&amp;": "&", "&lt;": "<", "&gt;": ">", "&nbsp;": " ",
        "&quot;": '"', "&#39;": "'",
    }
    for entity, char in entity_map.items():
        text = text.replace(entity, char)
    text = _HTML_ENTITY_RE.sub("", text)
    return text


# ---------------------------------------------------------------------------
# Anchor-text / href mismatch extractor (Future #3)
# Walks an HTML body and collects all (visible_text, href) pairs so that
# check_anchor_mismatch() can compare what the user sees vs where they go.
# Uses the stdlib html.parser — no external dependencies.
# ---------------------------------------------------------------------------
class _AnchorExtractor(HTMLParser):
    """Collect (link_text, href) tuples from an HTML string."""
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "a":
            self._current_href = dict(attrs).get("href", "")
            self._current_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "a" and self._current_href is not None:
            text = "".join(self._current_text).strip()
            if text and self._current_href:
                self.links.append((text, self._current_href))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data: str) -> None:
        if self._current_href is not None:
            self._current_text.append(data)


def _extract_anchors(html_body: str) -> list[tuple[str, str]]:
    """Return list of (visible_text, href) from an HTML email body."""
    parser = _AnchorExtractor()
    parser.feed(html_body)
    return parser.links


# ---------------------------------------------------------------------------
# Display-name spoof parser
# ---------------------------------------------------------------------------
_ANGLE_BRACKET_RE = re.compile(r"<([^>]+)>")

def _extract_address(sender: str) -> str:
    """Extract the bare email address from 'Display Name <addr>' format."""
    match = _ANGLE_BRACKET_RE.search(sender)
    return match.group(1).strip() if match else sender.strip()


def _extract_display_name(sender: str) -> str:
    """Return the display name portion, or empty string if none."""
    match = _ANGLE_BRACKET_RE.search(sender)
    if not match:
        return ""
    return sender[:match.start()].strip().strip('"').strip("'")


# ---------------------------------------------------------------------------
# Leet normalisation
# ---------------------------------------------------------------------------
_LEET_DIGIT_TO_LETTER: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g",
}

def _normalise_leet(text: str) -> str:
    """Replace common leet digits with their letter equivalents."""
    return "".join(_LEET_DIGIT_TO_LETTER.get(ch, ch) for ch in text)


# =============================================================================
# .EML FILE PARSER  (Future #1 + #2)
# Parses a raw RFC 5322 .eml file and returns a dict with:
#   sender, subject, body, reply_to, received_spf, dkim_result, dmarc_result,
#   return_path, reply_to_mismatch (bool), header_warnings (list[str])
# =============================================================================

def parse_eml(raw_bytes: bytes) -> dict:
    """
    Parse a raw .eml file (bytes) using Python's stdlib email module.

    Returns a dict with all fields needed by analyze_email(), plus header
    metadata for the new header-analysis rule.

    Security note: the file is parsed in memory only. No URLs are fetched,
    no external lookups are made, and nothing is written to disk.
    """
    msg = email.message_from_bytes(raw_bytes, policy=email_policy.default)

    # ── Core fields ──────────────────────────────────────────────────────────
    sender  = str(msg.get("From",    "") or "")
    subject = str(msg.get("Subject", "") or "")
    reply_to     = str(msg.get("Reply-To",    "") or "")
    return_path  = str(msg.get("Return-Path", "") or "")
    received_spf = str(msg.get("Received-SPF", "") or "")
    dkim_result  = str(msg.get("DKIM-Signature", "") or "")
    # Authentication-Results header often bundles SPF + DKIM + DMARC together
    auth_results = str(msg.get("Authentication-Results", "") or "")

    # ── Body extraction ───────────────────────────────────────────────────────
    # Walk the MIME tree and collect all text parts (prefer plain, fall back
    # to HTML).  HTML parts are stripped before analysis.
    plain_parts: list[str] = []
    html_parts:  list[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                plain_parts.append(part.get_content())
            elif ctype == "text/html":
                html_parts.append(part.get_content())
    else:
        ctype = msg.get_content_type()
        content = msg.get_content()
        if ctype == "text/plain":
            plain_parts.append(content)
        elif ctype == "text/html":
            html_parts.append(content)

    if plain_parts:
        body = "\n".join(plain_parts)
    elif html_parts:
        body = _strip_html("\n".join(html_parts))
    else:
        body = ""

    # ── Header analysis warnings ──────────────────────────────────────────────
    # These are informational notes surfaced in the UI; they are separate from
    # the five scoring rules and do not contribute to the risk score directly.
    # (Rationale: SPF/DKIM/DMARC outcomes require DNS validation we cannot do
    # locally; we can only report what the receiving server recorded in headers.)
    header_warnings: list[str] = []

    # Reply-To ≠ From mismatch
    reply_to_addr  = _extract_address(reply_to).lower()
    from_addr      = _extract_address(sender).lower()
    reply_to_mismatch = bool(
        reply_to_addr
        and from_addr
        and reply_to_addr != from_addr
    )
    if reply_to_mismatch:
        header_warnings.append(
            f"Reply-To address ({reply_to_addr}) differs from From address "
            f"({from_addr}). Replies would go to a different mailbox — a common "
            "phishing technique to intercept responses."
        )

    # SPF result
    spf_lower = received_spf.lower()
    if "fail" in spf_lower:
        header_warnings.append(
            "SPF check FAILED — the sending server is not authorised to send "
            "email on behalf of this domain."
        )
    elif "softfail" in spf_lower:
        header_warnings.append(
            "SPF check SOFTFAIL — the sending server is not strongly authorised "
            "for this domain."
        )
    elif not spf_lower and not auth_results:
        header_warnings.append(
            "No SPF result found in headers — the receiving server may not have "
            "checked sender authorisation."
        )

    # DKIM
    auth_lower = auth_results.lower()
    if "dkim=fail" in auth_lower:
        header_warnings.append(
            "DKIM signature FAILED — the message may have been modified in transit "
            "or the signature is forged."
        )
    elif "dkim=none" in auth_lower:
        header_warnings.append(
            "No DKIM signature found — the sending domain has not signed this message."
        )

    # DMARC
    if "dmarc=fail" in auth_lower:
        header_warnings.append(
            "DMARC check FAILED — the message does not align with the domain's "
            "published email authentication policy."
        )

    # Return-Path ≠ From domain mismatch (envelope sender spoofing)
    rp_addr  = _extract_address(return_path).lower()
    rp_domain = rp_addr.split("@")[-1] if "@" in rp_addr else ""
    fr_domain = from_addr.split("@")[-1] if "@" in from_addr else ""
    if rp_domain and fr_domain and rp_domain != fr_domain:
        header_warnings.append(
            f"Return-Path domain ({rp_domain}) differs from From domain "
            f"({fr_domain}). Bounce messages would go to a different domain — "
            "common in spoofed email."
        )

    return {
        "sender":            sender,
        "subject":           subject,
        "body":              body,
        "reply_to":          reply_to,
        "return_path":       return_path,
        "received_spf":      received_spf,
        "dkim_result":       dkim_result,
        "auth_results":      auth_results,
        "reply_to_mismatch": reply_to_mismatch,
        "header_warnings":   header_warnings,
        # Pass raw HTML parts through so the anchor-mismatch rule can use them
        "_html_parts":       html_parts,
    }


# =============================================================================
# DETECTION ENGINE
# =============================================================================
# SCORING WEIGHTS:
#   Urgency language        — up to 20 pts  (scaled by match density)
#   Credential request      — up to 25 pts  (scaled by match density)
#   Suspicious URL          — 20 pts (binary)
#   Sender inconsistency    — 20 pts (binary)
#   Sensitive info request  — up to 15 pts  (scaled by match density)
#   Anchor text mismatch    — up to 15 pts  (new — scaled by mismatch count)
#
# CO-OCCURRENCE BONUS: +10 pts when 3+ rules fire.
#
# CLASSIFICATION THRESHOLDS:
#   Low  0–29 · Medium 30–59 · High 60–100  (score capped at 100)
# =============================================================================

# ---------------------------------------------------------------------------
# Sample emails (used by app.py only — defined here so they travel with engine)
# ---------------------------------------------------------------------------
SAMPLE_EMAILS = {
    "— select a sample —": {"sender": "", "subject": "", "body": ""},
    "🔴 Sample A — Credential Harvest": {
        "sender": "security-alert@paypa1-support.com",
        "subject": "URGENT: Your account has been suspended",
        "body": (
            "Dear Customer,\n\n"
            "We have detected unusual activity on your PayPal account. "
            "Your account has been temporarily suspended.\n\n"
            "You MUST verify your credentials immediately or your account "
            "will be permanently closed within 24 hours.\n\n"
            "Click here to verify: http://192.168.99.1/paypal-login\n\n"
            "Enter your username, password, and credit card number to restore access.\n\n"
            "PayPal Security Team"
        ),
    },
    "🟡 Sample B — Suspicious Link": {
        "sender": "newsletter@shop-deals.net",
        "subject": "You have won a prize! Claim now",
        "body": (
            "Hello,\n\n"
            "Congratulations! You have been selected for an exclusive reward.\n\n"
            "Claim your gift card here: https://bit.ly/3xClaimNow\n\n"
            "Offer expires soon. Act fast!\n\n"
            "Deals Team"
        ),
    },
    "🟢 Sample C — Legitimate-looking Internal Email": {
        "sender": "hr@acmecorp.com",
        "subject": "Updated holiday schedule for Q4",
        "body": (
            "Hi Team,\n\n"
            "Please find the updated holiday schedule for Q4 attached.\n\n"
            "If you have any questions, reply to this email or contact HR directly.\n\n"
            "Best regards,\n"
            "ACME Corp HR Department"
        ),
    },
    "🔴 Sample D — Display-Name Spoof": {
        "sender": '"FedEx Delivery" <noreply@parcel-track99.ru>',
        "subject": "Your FedEx package could not be delivered",
        "body": (
            "Dear Customer,\n\n"
            "We attempted to deliver your package but nobody was available.\n\n"
            "To reschedule delivery, please verify your address and provide "
            "your date of birth and driver's license number.\n\n"
            "Track your shipment: https://tinyurl.com/fedex-redeliver\n\n"
            "FedEx Customer Service"
        ),
    },
    "🔴 Sample E — Anchor Text Mismatch": {
        "sender": "noreply@secure-paypal-alert.com",
        "subject": "Verify your PayPal account",
        "body": (
            "Dear Customer,\n\n"
            "Your PayPal account requires verification. Click the link below:\n\n"
            '<a href="http://192.168.50.1/steal-creds">https://www.paypal.com/verify</a>\n\n'
            "Failure to verify will result in account suspension.\n\n"
            "PayPal Support"
        ),
    },
}

# ---------------------------------------------------------------------------
# Rule 1 — Urgency language (weight: up to 20, scaled)
# ---------------------------------------------------------------------------
URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bexpires?\b",
    r"\bwithin \d+ hours?\b", r"\bwithin \d+ days?\b", r"\bfinal notice\b",
    r"\blast chance\b", r"\bverify (now|immediately|your account)\b",
    r"\baccount (suspended|closed|locked|disabled)\b",
    r"\bunusual activity\b", r"\bsuspicious (activity|login|sign.?in)\b",
    r"\byour account (will be|has been)\b",
    r"\baction required\b", r"\bresponse required\b", r"\btime.sensitive\b",
]

def check_urgency(sender: str, subject: str, body: str) -> dict | None:
    """
    Detect urgency / fear language in the subject and body.
    Weight scaled: 1 match = 10 pts, 2 = 15 pts, 3+ = 20 pts.
    """
    combined = _strip_html(subject + " " + body).lower()
    matched_patterns = [p for p in URGENCY_PATTERNS if re.search(p, combined)]
    if not matched_patterns:
        return None

    n = len(matched_patterns)
    weight = 10 if n == 1 else (15 if n == 2 else 20)

    matched_text = []
    for p in matched_patterns[:3]:
        m = re.search(p, combined)
        if m:
            matched_text.append(f'"{m.group(0)}"')

    return {
        "indicator": "Urgency / Fear Language",
        "detail": (
            f"Found {n} urgency phrase(s) such as: "
            + ", ".join(matched_text)
            + ". Phishing emails frequently use artificial time pressure "
            "to prevent careful evaluation."
        ),
        "weight": weight,
        "advice": (
            "Slow down. Legitimate organisations rarely demand immediate action "
            "via email. Verify directly through the official website or phone "
            "number — not through any link in this email."
        ),
    }


# ---------------------------------------------------------------------------
# Rule 2 — Credential request (weight: up to 25, scaled)
# ---------------------------------------------------------------------------
CREDENTIAL_PATTERNS = [
    r"\benter your (username|password|login|credentials|pin)\b",
    r"\bverify your (credentials|account|identity|login|password)\b",
    r"\bconfirm your (password|account|details|credentials)\b",
    r"\bupdate your (password|payment|billing|card)\b",
    r"\bprovide your (credentials|account details|password|card number)\b",
    r"\bsubmit your (password|credentials|card|pin)\b",
    r"\bsign in to (verify|confirm|restore|reactivate)\b",
    r"\bcredit card\b", r"\bcard number\b", r"\bcvv\b", r"\bsecurity code\b",
    r"\bexpiry date\b", r"\bcard details\b",
]

def check_credential_request(sender: str, subject: str, body: str) -> dict | None:
    """
    Detect explicit requests for credentials or payment card details.
    Weight scaled: 1–2 matches = 15 pts, 3+ = 25 pts.
    """
    combined = _strip_html(subject + " " + body).lower()
    matched = [p for p in CREDENTIAL_PATTERNS if re.search(p, combined)]
    if not matched:
        return None
    weight = 15 if len(matched) <= 2 else 25
    return {
        "indicator": "Credential / Payment Request",
        "detail": (
            f"The email contains {len(matched)} phrase(s) explicitly requesting "
            "credentials or payment details. "
            "Legitimate services never ask for passwords or card details by email."
        ),
        "weight": weight,
        "advice": (
            "Never enter credentials or payment details by following a link in an "
            "email. Navigate directly to the official site and log in from there."
        ),
    }


# ---------------------------------------------------------------------------
# Rule 3 — Suspicious URL patterns (weight: 20)
# Scans both subject and body. URLs are never fetched or resolved.
# ---------------------------------------------------------------------------
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd",
    "buff.ly", "short.link", "rebrand.ly", "clck.ru",
    "cutt.ly", "rb.gy", "tiny.cc",
]

URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
IP_IN_URL  = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")

def _has_digit_substitution(domain: str) -> bool:
    """Flag domains with letter+digit mixing inside word segments."""
    for part in domain.split(".")[:-1]:
        if re.search(r"[a-z]\d|\d[a-z]", part, re.IGNORECASE):
            return True
    return False

def check_suspicious_urls(sender: str, subject: str, body: str) -> dict | None:
    """
    Scan subject and body for suspicious URL characteristics:
    IP-address host, known URL shortener, leet-substituted lookalike domain.
    """
    combined_text = _strip_html(subject + " " + body)
    urls = URL_REGEX.findall(combined_text)
    if not urls:
        return None

    reasons: list[str] = []
    seen_hosts: set[str] = set()

    for url in urls:
        if IP_IN_URL.match(url):
            reasons.append(f"IP-address URL: {url[:70]}")
        for shortener in URL_SHORTENERS:
            if shortener in url.lower():
                reasons.append(f"URL shortener ({shortener}): {url[:70]}")
                break
        host_match = re.match(r"https?://([^/?\s]+)", url, re.IGNORECASE)
        if host_match:
            host = host_match.group(1).lower()
            if host not in seen_hosts and _has_digit_substitution(host):
                reasons.append(f"Possible lookalike domain: {host}")
            seen_hosts.add(host)

    if not reasons:
        return None
    return {
        "indicator": "Suspicious URL Pattern",
        "detail": (
            "Suspicious URL characteristic(s) found:\n- "
            + "\n- ".join(reasons)
            + "\n\nPhishers use IP addresses, URL shorteners, and lookalike "
            "domains to disguise malicious destinations."
        ),
        "weight": 20,
        "advice": (
            "Do not click any links in this email. Type the official address "
            "directly into your browser. Hover over links to preview the true "
            "destination before clicking."
        ),
    }


# ---------------------------------------------------------------------------
# Rule 4 — Sender inconsistency (weight: 20)
# ---------------------------------------------------------------------------
BRAND_DOMAINS: dict[str, str] = {
    "paypal": "paypal.com", "amazon": "amazon.com", "apple": "apple.com",
    "microsoft": "microsoft.com", "google": "google.com", "netflix": "netflix.com",
    "facebook": "facebook.com", "instagram": "instagram.com", "twitter": "twitter.com",
    "linkedin": "linkedin.com", "dropbox": "dropbox.com",
    "chase": "chase.com", "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com", "citibank": "citibank.com",
    "barclays": "barclays.co.uk", "hsbc": "hsbc.com",
    "fedex": "fedex.com", "ups": "ups.com", "dhl": "dhl.com", "usps": "usps.com",
    "irs": "irs.gov", "hmrc": "hmrc.gov.uk",
}

FREE_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "protonmail.com", "icloud.com", "mail.com",
]

def check_sender_inconsistency(sender: str, subject: str, body: str) -> dict | None:
    """
    Three sub-checks:
    1. Display-name spoof — display name contains a brand, domain does not match.
    2. Lookalike domain — domain resembles a brand (with leet normalisation).
    3. Free-provider impersonation — free mail + brand mention in content.
    """
    real_address = _extract_address(sender).lower()
    display_name = _extract_display_name(sender).lower()

    domain_match = re.search(r"@([\w.\-]+)", real_address)
    if not domain_match:
        return None
    domain = domain_match.group(1)
    domain_normalised = _normalise_leet(domain)

    reasons: list[str] = []

    if display_name:
        for brand, official_domain in BRAND_DOMAINS.items():
            if brand in display_name and domain != official_domain:
                reasons.append(
                    f'Display name contains "{brand}" but email is sent from '
                    f'"{domain}", not the official domain "{official_domain}".'
                )

    for brand, official_domain in BRAND_DOMAINS.items():
        if (brand in domain or brand in domain_normalised) and domain != official_domain:
            already = any(f'"{brand}"' in r for r in reasons)
            if not already:
                reasons.append(
                    f'Sender domain "{domain}" resembles "{brand}" '
                    f'but is not the official domain "{official_domain}".'
                )

    if domain in FREE_PROVIDERS:
        combined = _strip_html(subject + " " + body).lower()
        for brand in BRAND_DOMAINS:
            if brand in combined:
                reasons.append(
                    f'Email sent from a free provider ("{domain}") '
                    f'but mentions the brand "{brand}" — '
                    "legitimate companies email from their own domains."
                )
                break

    if not reasons:
        return None
    return {
        "indicator": "Sender Inconsistency",
        "detail": " ".join(reasons),
        "weight": 20,
        "advice": (
            "Check the actual From: address carefully, not just the display name. "
            "Real companies email from their own verified domains. When in doubt, "
            "contact the company through their official website."
        ),
    }


# ---------------------------------------------------------------------------
# Rule 5 — Sensitive PII request (weight: up to 15, scaled)
# ---------------------------------------------------------------------------
SENSITIVE_PATTERNS = [
    r"\bsocial security\b", r"\bssn\b", r"\bdate of birth\b", r"\bdob\b",
    r"\bbank account\b", r"\baccount number\b", r"\brouting number\b",
    r"\bpassport\b", r"\bdriver'?s? licen[sc]e\b", r"\bmother'?s maiden\b",
    r"\bmedical record\b", r"\binsurance (number|id|policy)\b",
    r"\btax (id|number|return)\b", r"\bein\b", r"\bnational id\b",
    r"\bidentity (card|document|number)\b",
]

def check_sensitive_info_request(sender: str, subject: str, body: str) -> dict | None:
    """
    Detect PII requests beyond credentials.
    Weight scaled: 1 match = 10 pts, 2+ = 15 pts.
    """
    combined = _strip_html(subject + " " + body).lower()
    matched = [p for p in SENSITIVE_PATTERNS if re.search(p, combined)]
    if not matched:
        return None
    weight = 10 if len(matched) == 1 else 15
    return {
        "indicator": "Sensitive PII Request",
        "detail": (
            f"Found {len(matched)} reference(s) to sensitive personal information "
            "(e.g. SSN, bank account, date of birth). "
            "Legitimate organisations rarely need this information via email."
        ),
        "weight": weight,
        "advice": (
            "Never provide government ID numbers, bank account details, or other "
            "sensitive PII in response to an unsolicited email. Contact the "
            "requesting organisation directly to verify."
        ),
    }


# ---------------------------------------------------------------------------
# Rule 6 — Anchor text / href mismatch  (Future #3)
# Detects links where the visible text looks like a trusted URL but the
# actual href points somewhere different.
# Weight: 10 pts (1 mismatch) · 15 pts (2+ mismatches)
# Rationale: this is a classic phishing technique in HTML emails — the user
# sees 'https://www.paypal.com' but clicking goes to a malicious host.
# Only active when the body contains HTML anchor tags.
# ---------------------------------------------------------------------------
_URL_LIKE = re.compile(r"https?://([^\s/\"'>]+)", re.IGNORECASE)

def check_anchor_mismatch(sender: str, subject: str, body: str) -> dict | None:
    """
    Compare the visible anchor text against the href in HTML email bodies.
    Flags links where the text looks like a legitimate URL but the href
    points to a different host.
    """
    anchors = _extract_anchors(body)
    if not anchors:
        return None

    mismatches: list[str] = []
    for text, href in anchors:
        text_match = _URL_LIKE.search(text.strip())
        href_match = _URL_LIKE.search(href.strip())
        if not text_match or not href_match:
            continue
        text_host = text_match.group(1).lower().rstrip(".,;")
        href_host = href_match.group(1).lower().rstrip(".,;")
        if text_host != href_host:
            mismatches.append(
                f'Visible text shows "{text_host}" but link points to "{href_host}"'
            )

    if not mismatches:
        return None

    weight = 10 if len(mismatches) == 1 else 15
    return {
        "indicator": "Anchor Text / Link Mismatch",
        "detail": (
            f"Found {len(mismatches)} link(s) where the visible text shows a "
            "different URL than the actual destination:\n- "
            + "\n- ".join(mismatches[:3])
            + "\n\nThis is a classic phishing technique to disguise malicious "
            "links as trusted ones."
        ),
        "weight": weight,
        "advice": (
            "Never trust the visible text of a link. Hover over it to see the "
            "real destination in your browser's status bar, or right-click to "
            "copy and inspect the URL before visiting."
        ),
    }


# ---------------------------------------------------------------------------
# Core analysis function
# ---------------------------------------------------------------------------
RULES = [
    check_urgency,
    check_credential_request,
    check_suspicious_urls,
    check_sender_inconsistency,
    check_sensitive_info_request,
    check_anchor_mismatch,          # new Rule 6
]

CO_OCCURRENCE_BONUS = 10

def analyze_email(sender: str, subject: str, body: str) -> dict:
    """
    Run every detection rule and return a structured result.

    Returns:
        {
          "score":       int,          # 0–100, capped
          "risk_level":  str,          # "Low", "Medium", or "High"
          "findings":    list[dict],   # one dict per triggered rule
          "bonus":       int,          # co-occurrence bonus (0 or 10)
        }
    """
    findings: list[dict] = []
    total_score = 0

    for rule in RULES:
        result = rule(sender, subject, body)
        if result is not None:
            findings.append(result)
            total_score += result["weight"]

    bonus = 0
    if len(findings) >= 3:
        bonus = CO_OCCURRENCE_BONUS
        total_score += bonus

    total_score = min(total_score, 100)

    if total_score >= 60:
        risk_level = "High"
    elif total_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "score":      total_score,
        "risk_level": risk_level,
        "findings":   findings,
        "bonus":      bonus,
    }


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------
def validate_inputs(sender: str, subject: str, body: str) -> list[str]:
    """
    Validate fields before analysis. Returns a list of error strings.
    Empty list = all inputs are acceptable.
    """
    errors: list[str] = []
    MAX_SENDER  = 320
    MAX_SUBJECT = 998
    MAX_BODY    = 50_000

    real_address = _extract_address(sender)
    if real_address and "@" not in real_address:
        errors.append(
            "The sender address does not look valid — it must contain an '@' symbol."
        )
    if len(sender) > MAX_SENDER:
        errors.append(f"Sender address is too long (max {MAX_SENDER} characters).")
    if len(subject) > MAX_SUBJECT:
        errors.append(f"Subject line is too long (max {MAX_SUBJECT} characters).")
    if len(body) > MAX_BODY:
        errors.append(
            f"Email body is too long (max {MAX_BODY:,} characters). "
            "Please paste plain text only."
        )
    return errors


# ---------------------------------------------------------------------------
# CSV export helper
# ---------------------------------------------------------------------------
def build_csv_report(sender: str, subject: str, result: dict) -> str:
    """Return a CSV-formatted string summarising the analysis result."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Field", "Value"])
    writer.writerow(["Sender",     sender])
    writer.writerow(["Subject",    subject])
    writer.writerow(["Score",      result["score"]])
    writer.writerow(["Risk Level", result["risk_level"]])
    writer.writerow([])
    writer.writerow(["Indicator", "Weight (pts)", "Detail"])
    for f in result["findings"]:
        writer.writerow([f["indicator"], f["weight"],
                         f["detail"].replace("\n", " ")])
    if result["bonus"]:
        writer.writerow(["Co-occurrence bonus", result["bonus"],
                         "3 or more indicators triggered simultaneously"])
    return output.getvalue()
