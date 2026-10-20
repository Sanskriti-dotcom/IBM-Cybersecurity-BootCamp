# =============================================================================
# PhishGuard — Test Suite
# Run with:  python3 tests.py
# Uses Python's built-in unittest + hypothesis for property-based tests.
# Install hypothesis with:  pip install hypothesis
# =============================================================================

import sys
import unittest

# ---------------------------------------------------------------------------
# Direct import from engine.py — no exec-bootstrap needed now that the
# engine is a proper module.
# ---------------------------------------------------------------------------
from engine import (
    analyze_email,
    validate_inputs,
    build_csv_report,
    parse_eml,
    check_urgency,
    check_credential_request,
    check_suspicious_urls,
    check_sender_inconsistency,
    check_sensitive_info_request,
    check_anchor_mismatch,
    _strip_html,
    _extract_address,
    _extract_display_name,
    _normalise_leet,
    _extract_anchors,
    RULES,
)

# ---------------------------------------------------------------------------
# Hypothesis — property-based tests (Future #9)
# Skip gracefully if not installed.
# ---------------------------------------------------------------------------
try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False


# =============================================================================
class TestHTMLStripper(unittest.TestCase):
    """HTML tag and entity stripping."""

    def test_strips_html_tags(self):
        result = _strip_html("<b>URGENT</b> — verify your account")
        self.assertNotIn("<b>", result)
        self.assertIn("URGENT", result)

    def test_decodes_named_entity(self):
        self.assertIn("&", _strip_html("please &amp; verify"))

    def test_strips_encoded_keyword_evasion(self):
        result = _strip_html("&#85;RGENT action")
        self.assertIn("RGENT", result)

    def test_plain_text_unchanged(self):
        text = "Hello, this is a normal email."
        self.assertEqual(_strip_html(text), text)


# =============================================================================
class TestAnchorExtractor(unittest.TestCase):
    """HTML anchor text / href extraction."""

    def test_extracts_single_anchor(self):
        html = '<a href="http://evil.com">https://www.paypal.com</a>'
        links = _extract_anchors(html)
        self.assertEqual(len(links), 1)
        text, href = links[0]
        self.assertIn("paypal", text)
        self.assertIn("evil", href)

    def test_no_anchors_returns_empty(self):
        self.assertEqual(_extract_anchors("No links here."), [])

    def test_anchor_without_text_ignored(self):
        html = '<a href="http://evil.com"></a>'
        self.assertEqual(_extract_anchors(html), [])

    def test_multiple_anchors(self):
        html = (
            '<a href="http://a.com">https://b.com</a> '
            '<a href="http://c.com">https://d.com</a>'
        )
        self.assertEqual(len(_extract_anchors(html)), 2)


# =============================================================================
class TestDisplayNameParser(unittest.TestCase):
    """Display-name spoof format parsing."""

    def test_extracts_address_from_angle_bracket_format(self):
        self.assertEqual(_extract_address('"PayPal" <attacker@evil.com>'), "attacker@evil.com")

    def test_extracts_display_name(self):
        self.assertEqual(_extract_display_name('"PayPal Support" <a@b.com>'), "PayPal Support")

    def test_plain_address_unchanged(self):
        self.assertEqual(_extract_address("user@example.com"), "user@example.com")

    def test_no_display_name_returns_empty(self):
        self.assertEqual(_extract_display_name("user@example.com"), "")


# =============================================================================
class TestLeetNormaliser(unittest.TestCase):
    """Leet digit-to-letter mapping."""

    def test_paypa1_normalises_to_paypal(self):
        self.assertEqual(_normalise_leet("paypa1"), "paypal")

    def test_g00gle_normalises_to_google(self):
        self.assertEqual(_normalise_leet("g00gle"), "google")

    def test_clean_word_unchanged(self):
        self.assertEqual(_normalise_leet("amazon"), "amazon")

    def test_each_digit_maps_correctly(self):
        expected = {"0": "o", "1": "l", "3": "e", "4": "a",
                    "5": "s", "6": "g", "7": "t", "8": "b", "9": "g"}
        for digit, letter in expected.items():
            self.assertEqual(_normalise_leet(digit), letter)


# =============================================================================
class TestUrgencyRule(unittest.TestCase):
    """Rule 1 — Urgency / Fear Language (proportional weight)."""

    def test_single_match_gives_10_pts(self):
        r = check_urgency("", "Offer expires today", "")
        self.assertIsNotNone(r)
        self.assertEqual(r["weight"], 10)

    def test_two_matches_gives_15_pts(self):
        r = check_urgency("", "URGENT: act now", "")
        self.assertIsNotNone(r)
        self.assertEqual(r["weight"], 15)

    def test_three_plus_matches_gives_20_pts(self):
        r = check_urgency("", "URGENT action required",
                          "Account suspended. Verify immediately within 24 hours.")
        self.assertIsNotNone(r)
        self.assertEqual(r["weight"], 20)

    def test_clean_email_returns_none(self):
        self.assertIsNone(check_urgency("", "Meeting notes", "See agenda attached."))

    def test_detail_has_no_backslash_b(self):
        r = check_urgency("", "URGENT verify now", "Account suspended immediately.")
        self.assertIsNotNone(r)
        self.assertNotIn(r"\b", r["detail"])

    def test_html_encoded_urgency_detected(self):
        r = check_urgency("", "<b>URGENT</b>", "account <i>suspended</i>")
        self.assertIsNotNone(r)

    def test_new_patterns_detected(self):
        self.assertIsNotNone(check_urgency("", "Action required", "time-sensitive matter."))


# =============================================================================
class TestCredentialRule(unittest.TestCase):
    """Rule 2 — Credential / Payment Request (tightened + proportional)."""

    def test_explicit_enter_password_detected(self):
        self.assertIsNotNone(check_credential_request("", "", "Enter your password."))

    def test_bare_password_word_no_longer_triggers(self):
        r = check_credential_request(
            "", "Password reset", "Your password has been changed."
        )
        self.assertIsNone(r)

    def test_bare_pin_word_no_longer_triggers(self):
        self.assertIsNone(check_credential_request("", "Security tip", "Keep your pin safe."))

    def test_credit_card_detected(self):
        self.assertIsNotNone(check_credential_request("", "", "Provide your credit card."))

    def test_few_matches_give_15_pts(self):
        r = check_credential_request("", "", "Enter your password to verify.")
        self.assertIsNotNone(r)
        self.assertEqual(r["weight"], 15)

    def test_many_matches_give_25_pts(self):
        r = check_credential_request(
            "", "",
            "Enter your password. Confirm your credentials. Provide your card number. "
            "Update your payment. Submit your CVV."
        )
        self.assertIsNotNone(r)
        self.assertEqual(r["weight"], 25)

    def test_clean_email_returns_none(self):
        self.assertIsNone(check_credential_request("", "Invoice", "Please review."))


# =============================================================================
class TestSuspiciousURLRule(unittest.TestCase):
    """Rule 3 — Suspicious URL (scans subject too)."""

    def test_ip_address_url(self):
        r = check_suspicious_urls("", "", "Click: http://192.168.1.1/login")
        self.assertIsNotNone(r)
        self.assertEqual(r["weight"], 20)

    def test_shortener_in_body(self):
        self.assertIsNotNone(check_suspicious_urls("", "", "https://bit.ly/abc123"))

    def test_lookalike_domain(self):
        self.assertIsNotNone(check_suspicious_urls("", "", "https://paypa1.com/secure"))

    def test_shortener_in_subject(self):
        self.assertIsNotNone(check_suspicious_urls("", "See https://bit.ly/abc", "Hi."))

    def test_clean_url_returns_none(self):
        self.assertIsNone(check_suspicious_urls("", "", "Visit https://www.acmecorp.com"))

    def test_no_urls_returns_none(self):
        self.assertIsNone(check_suspicious_urls("", "", "No links here."))

    def test_new_shortener_cutt_ly(self):
        self.assertIsNotNone(check_suspicious_urls("", "", "https://cutt.ly/example"))


# =============================================================================
class TestSenderInconsistencyRule(unittest.TestCase):
    """Rule 4 — Sender Inconsistency."""

    def test_lookalike_paypal_domain(self):
        r = check_sender_inconsistency("security@paypa1-support.com", "", "PayPal notice.")
        self.assertIsNotNone(r)
        self.assertEqual(r["weight"], 20)

    def test_free_provider_impersonating_brand(self):
        r = check_sender_inconsistency("alerts@gmail.com", "", "Your Amazon order.")
        self.assertIsNotNone(r)

    def test_display_name_spoof_detected(self):
        r = check_sender_inconsistency('"PayPal Support" <noreply@evil.com>', "", "")
        self.assertIsNotNone(r)
        self.assertIn("Display name", r["detail"])

    def test_expanded_brand_fedex(self):
        r = check_sender_inconsistency("tracking@fedex-delivery.net", "", "FedEx package.")
        self.assertIsNotNone(r)

    def test_expanded_brand_irs(self):
        r = check_sender_inconsistency("refund@irs-gov-refund.com", "", "IRS refund.")
        self.assertIsNotNone(r)

    def test_legitimate_sender_returns_none(self):
        self.assertIsNone(check_sender_inconsistency("hr@acmecorp.com", "", "Team update."))

    def test_malformed_sender_returns_none(self):
        self.assertIsNone(check_sender_inconsistency("not-an-email", "", ""))


# =============================================================================
class TestSensitiveInfoRule(unittest.TestCase):
    """Rule 5 — Sensitive PII Request (proportional weight)."""

    def test_single_match_gives_10_pts(self):
        r = check_sensitive_info_request("", "", "Provide your passport.")
        self.assertIsNotNone(r)
        self.assertEqual(r["weight"], 10)

    def test_multiple_matches_give_15_pts(self):
        r = check_sensitive_info_request("", "", "SSN, bank account, date of birth.")
        self.assertIsNotNone(r)
        self.assertEqual(r["weight"], 15)

    def test_national_id_pattern(self):
        self.assertIsNotNone(check_sensitive_info_request("", "", "Send your national id."))

    def test_clean_email_returns_none(self):
        self.assertIsNone(check_sensitive_info_request("", "Holiday schedule", "Party!"))


# =============================================================================
class TestAnchorMismatchRule(unittest.TestCase):
    """Rule 6 — Anchor Text / Link Mismatch (new)."""

    def test_detects_mismatch(self):
        body = '<a href="http://192.168.50.1/steal">https://www.paypal.com/verify</a>'
        r = check_anchor_mismatch("", "", body)
        self.assertIsNotNone(r)
        self.assertIn("paypal", r["detail"])
        self.assertIn("192.168", r["detail"])

    def test_matching_urls_returns_none(self):
        body = '<a href="https://www.paypal.com/verify">https://www.paypal.com/verify</a>'
        self.assertIsNone(check_anchor_mismatch("", "", body))

    def test_no_html_anchors_returns_none(self):
        self.assertIsNone(check_anchor_mismatch("", "", "Visit paypal.com today."))

    def test_single_mismatch_gives_10_pts(self):
        body = '<a href="http://evil.com">https://www.amazon.com</a>'
        r = check_anchor_mismatch("", "", body)
        self.assertIsNotNone(r)
        self.assertEqual(r["weight"], 10)

    def test_multiple_mismatches_give_15_pts(self):
        body = (
            '<a href="http://evil.com">https://www.amazon.com</a> '
            '<a href="http://bad.net">https://www.paypal.com</a>'
        )
        r = check_anchor_mismatch("", "", body)
        self.assertIsNotNone(r)
        self.assertEqual(r["weight"], 15)

    def test_sample_e_is_detected(self):
        """Sample E body should trigger anchor mismatch."""
        body = (
            'Your PayPal account requires verification.\n'
            '<a href="http://192.168.50.1/steal-creds">https://www.paypal.com/verify</a>'
        )
        r = check_anchor_mismatch("", "", body)
        self.assertIsNotNone(r)


# =============================================================================
class TestEmlParser(unittest.TestCase):
    """parse_eml() — .eml file parsing and header analysis."""

    def _make_eml(self, from_: str, subject: str, body: str,
                  reply_to: str = "", spf: str = "",
                  auth_results: str = "", return_path: str = "") -> bytes:
        """Build a minimal RFC 5322 .eml bytes object for testing."""
        headers = f"From: {from_}\r\nSubject: {subject}\r\n"
        if reply_to:
            headers += f"Reply-To: {reply_to}\r\n"
        if spf:
            headers += f"Received-SPF: {spf}\r\n"
        if auth_results:
            headers += f"Authentication-Results: {auth_results}\r\n"
        if return_path:
            headers += f"Return-Path: {return_path}\r\n"
        headers += "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        return (headers + body).encode("utf-8")

    def test_extracts_sender_and_subject(self):
        raw = self._make_eml("attacker@evil.com", "URGENT notice", "Click here.")
        p = parse_eml(raw)
        self.assertIn("attacker@evil.com", p["sender"])
        self.assertIn("URGENT", p["subject"])

    def test_extracts_plain_body(self):
        raw = self._make_eml("a@b.com", "Test", "Hello world")
        p = parse_eml(raw)
        self.assertIn("Hello world", p["body"])

    def test_reply_to_mismatch_detected(self):
        raw = self._make_eml(
            "support@paypal.com", "Account notice", "Body",
            reply_to="attacker@evil.com"
        )
        p = parse_eml(raw)
        self.assertTrue(p["reply_to_mismatch"])
        self.assertTrue(len(p["header_warnings"]) > 0)

    def test_no_reply_to_mismatch_when_same(self):
        raw = self._make_eml(
            "support@paypal.com", "Account notice", "Body",
            reply_to="support@paypal.com"
        )
        p = parse_eml(raw)
        self.assertFalse(p["reply_to_mismatch"])

    def test_spf_fail_generates_warning(self):
        raw = self._make_eml("a@b.com", "Subj", "Body", spf="fail")
        p = parse_eml(raw)
        self.assertTrue(any("SPF" in w for w in p["header_warnings"]))

    def test_dkim_fail_generates_warning(self):
        raw = self._make_eml(
            "a@b.com", "Subj", "Body",
            auth_results="example.com; dkim=fail"
        )
        p = parse_eml(raw)
        self.assertTrue(any("DKIM" in w for w in p["header_warnings"]))

    def test_dmarc_fail_generates_warning(self):
        raw = self._make_eml(
            "a@b.com", "Subj", "Body",
            auth_results="example.com; dmarc=fail"
        )
        p = parse_eml(raw)
        self.assertTrue(any("DMARC" in w for w in p["header_warnings"]))

    def test_return_path_domain_mismatch(self):
        raw = self._make_eml(
            "support@paypal.com", "Notice", "Body",
            return_path="<bounce@evil-domain.com>"
        )
        p = parse_eml(raw)
        self.assertTrue(any("Return-Path" in w for w in p["header_warnings"]))

    def test_clean_eml_no_hard_fail_warnings(self):
        """A minimal clean .eml should not trigger Reply-To, DKIM, DMARC, or
        Return-Path mismatch warnings. The 'no SPF result' notice may appear
        (informational) but no authentication-failure warnings should be present."""
        raw = self._make_eml("hr@acmecorp.com", "Holiday schedule", "Hi Team.")
        p = parse_eml(raw)
        self.assertFalse(p["reply_to_mismatch"])
        hard_fail_keywords = (
            "SPF check FAILED", "SPF check SOFTFAIL",
            "DKIM signature FAILED", "DMARC check FAILED", "Return-Path domain"
        )
        for w in p["header_warnings"]:
            self.assertFalse(
                any(kw in w for kw in hard_fail_keywords),
                f"Unexpected hard-fail warning in clean email: {w}"
            )


# =============================================================================
class TestAnalyzeEmail(unittest.TestCase):
    """Integration tests for the full pipeline."""

    def test_sample_a_is_high_risk(self):
        r = analyze_email(
            "security-alert@paypa1-support.com",
            "URGENT: Your account has been suspended",
            "You MUST verify your credentials immediately. "
            "Click: http://192.168.99.1/paypal-login "
            "Enter your password and credit card number.",
        )
        self.assertEqual(r["risk_level"], "High")
        self.assertGreaterEqual(r["score"], 60)

    def test_sample_b_is_medium_risk(self):
        r = analyze_email(
            "newsletter@shop-deals.net",
            "You have won a prize! Claim now",
            "Congratulations! Claim your gift: https://bit.ly/3xClaimNow "
            "Offer expires soon. Act fast!",
        )
        self.assertEqual(r["risk_level"], "Medium")
        self.assertGreaterEqual(r["score"], 30)
        self.assertLess(r["score"], 60)

    def test_sample_c_is_low_risk(self):
        r = analyze_email(
            "hr@acmecorp.com",
            "Updated holiday schedule for Q4",
            "Hi Team, please find the updated holiday schedule attached.",
        )
        self.assertEqual(r["risk_level"], "Low")
        self.assertEqual(r["score"], 0)
        self.assertEqual(len(r["findings"]), 0)

    def test_sample_e_anchor_mismatch_detected(self):
        body = (
            'Your PayPal account requires verification. '
            '<a href="http://192.168.50.1/steal-creds">https://www.paypal.com/verify</a> '
            "Failure to verify will result in account suspension."
        )
        r = analyze_email("noreply@secure-paypal-alert.com", "Verify your PayPal account", body)
        indicator_names = [f["indicator"] for f in r["findings"]]
        self.assertIn("Anchor Text / Link Mismatch", indicator_names)

    def test_empty_inputs_return_low(self):
        r = analyze_email("", "", "")
        self.assertEqual(r["risk_level"], "Low")
        self.assertEqual(r["score"], 0)

    def test_score_capped_at_100(self):
        r = analyze_email(
            "alert@paypa1-support.com",
            "URGENT: verify your account now",
            "Account suspended. Verify immediately at http://192.0.2.1/login. "
            "Enter your password, credit card number, and social security number. "
            "PayPal account closed within 24 hours.",
        )
        self.assertLessEqual(r["score"], 100)

    def test_co_occurrence_bonus_applied(self):
        r = analyze_email(
            "alert@paypa1-support.com",
            "URGENT: verify your account now",
            "Account suspended. Verify immediately at http://192.0.2.1/login. "
            "Enter your password and credit card number.",
        )
        self.assertEqual(r["bonus"], 10)

    def test_co_occurrence_bonus_not_applied_for_two_rules(self):
        r = analyze_email(
            "info@cleancompany.com",
            "Offer expires soon",
            "Act fast! See: https://bit.ly/offer",
        )
        self.assertEqual(r["bonus"], 0)

    def test_findings_have_required_keys(self):
        r = analyze_email("", "URGENT", "Enter your password immediately.")
        for f in r["findings"]:
            for key in ("indicator", "detail", "weight", "advice"):
                self.assertIn(key, f)

    def test_result_has_bonus_key(self):
        self.assertIn("bonus", analyze_email("", "", ""))

    def test_rules_list_includes_six_rules(self):
        """engine.py should now expose 6 rules including anchor mismatch."""
        self.assertEqual(len(RULES), 6)


# =============================================================================
class TestValidateInputs(unittest.TestCase):
    """Input validation helper."""

    def test_valid_inputs_no_errors(self):
        self.assertEqual(validate_inputs("user@example.com", "Hello", "Body"), [])

    def test_display_name_format_accepted(self):
        errors = validate_inputs('"PayPal" <support@paypal.com>', "Subject", "Body")
        self.assertEqual(errors, [])

    def test_missing_at_sign(self):
        errors = validate_inputs("notanemail", "Subject", "Body")
        self.assertTrue(any("'@'" in e for e in errors))

    def test_empty_sender_allowed(self):
        self.assertEqual(validate_inputs("", "Subject", "Body"), [])

    def test_sender_too_long(self):
        errors = validate_inputs("a" * 200 + "@" + "b" * 200 + ".com", "Sub", "Body")
        self.assertTrue(any("too long" in e.lower() for e in errors))

    def test_subject_too_long(self):
        self.assertTrue(any(
            "too long" in e.lower()
            for e in validate_inputs("a@b.com", "x" * 999, "Body")
        ))

    def test_body_too_long(self):
        self.assertTrue(any(
            "too long" in e.lower()
            for e in validate_inputs("a@b.com", "Subject", "x" * 50_001)
        ))

    def test_multiple_errors_reported(self):
        self.assertGreaterEqual(
            len(validate_inputs("notanemail", "Subject", "x" * 50_001)), 2
        )


# =============================================================================
class TestCSVReport(unittest.TestCase):
    """CSV export helper."""

    def _sample_a(self):
        return analyze_email(
            "security-alert@paypa1-support.com",
            "URGENT: Your account has been suspended",
            "Verify: http://192.168.99.1 Enter your credit card number.",
        )

    def test_csv_contains_score(self):
        result = self._sample_a()
        self.assertIn(str(result["score"]), build_csv_report("s@e.com", "Sub", result))

    def test_csv_contains_risk_level(self):
        result = self._sample_a()
        self.assertIn(result["risk_level"], build_csv_report("s@e.com", "Sub", result))

    def test_csv_contains_indicator_names(self):
        result = self._sample_a()
        csv_text = build_csv_report("s@e.com", "Sub", result)
        for f in result["findings"]:
            self.assertIn(f["indicator"], csv_text)

    def test_csv_bonus_row_when_bonus_applied(self):
        result = self._sample_a()
        if result["bonus"] > 0:
            self.assertIn("Co-occurrence bonus", build_csv_report("s@e.com", "Sub", result))

    def test_csv_is_valid_csv(self):
        import csv as csv_mod, io
        result = self._sample_a()
        rows = list(csv_mod.reader(io.StringIO(build_csv_report("s@e.com", "Sub", result))))
        self.assertGreater(len(rows), 3)


# =============================================================================
# PROPERTY-BASED TESTS  (Future #9 — requires: pip install hypothesis)
# Hypothesis decorators (@given, @settings) are only valid when hypothesis is
# actually installed. We conditionally define the class to avoid NameErrors
# at module parse time when hypothesis is absent.
# =============================================================================
if not HYPOTHESIS_AVAILABLE:
    class TestPropertyBased(unittest.TestCase):
        """Placeholder — install hypothesis to run property-based tests."""
        def test_skipped(self):
            self.skipTest("hypothesis not installed — run: pip install hypothesis")
else:
    class TestPropertyBased(unittest.TestCase):  # type: ignore[no-redef]
        """
        Property-based tests using Hypothesis.
        Generate random inputs to find edge cases hand-written tests miss.
        """

        @given(st.text())
        @settings(max_examples=200)
        def test_analyze_email_never_crashes(self, text):
            """analyze_email() must not raise for any string input."""
            try:
                result = analyze_email(text, text, text)
                self.assertIn(result["risk_level"], ("Low", "Medium", "High"))
                self.assertGreaterEqual(result["score"], 0)
                self.assertLessEqual(result["score"], 100)
            except Exception as e:
                self.fail(f"analyze_email raised unexpectedly: {e}")

        @given(st.text())
        @settings(max_examples=200)
        def test_validate_inputs_never_crashes(self, text):
            """validate_inputs() must always return a list, never raise."""
            self.assertIsInstance(validate_inputs(text, text, text), list)

        @given(st.text())
        @settings(max_examples=200)
        def test_strip_html_never_crashes(self, text):
            """_strip_html() must always return a string."""
            self.assertIsInstance(_strip_html(text), str)

        @given(st.text())
        @settings(max_examples=200)
        def test_score_is_always_in_range(self, text):
            """Score must always be 0–100 regardless of input."""
            result = analyze_email(text, text, text)
            self.assertGreaterEqual(result["score"], 0)
            self.assertLessEqual(result["score"], 100)

        @given(st.text(alphabet=st.characters(blacklist_categories=("Cs",))))
        @settings(max_examples=200)
        def test_extract_address_never_crashes(self, text):
            """_extract_address() must always return a string."""
            self.assertIsInstance(_extract_address(text), str)


# =============================================================================
if __name__ == "__main__":
    print("=" * 60)
    print("PhishGuard — Test Suite")
    if HYPOTHESIS_AVAILABLE:
        print("Hypothesis available — property-based tests will run.")
    else:
        print("Hypothesis not installed — skipping property-based tests.")
        print("Install with:  pip install hypothesis")
    print("=" * 60)
    unittest.main(verbosity=2)
