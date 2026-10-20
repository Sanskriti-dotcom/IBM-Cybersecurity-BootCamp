# =============================================================================
# PhishGuard — Streamlit UI
# All detection logic lives in engine.py.
# Run with:  streamlit run app.py
# =============================================================================

import streamlit as st
import pandas as pd
from engine import (
    SAMPLE_EMAILS, RULES,
    analyze_email, validate_inputs, build_csv_report, parse_eml,
)

# ---------------------------------------------------------------------------
# Page configuration
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered",
)

# ---------------------------------------------------------------------------
# Session-state initialisation
# ---------------------------------------------------------------------------
if "total_analyzed" not in st.session_state:
    st.session_state["total_analyzed"] = 0
if "risk_counts" not in st.session_state:
    st.session_state["risk_counts"] = {"Low": 0, "Medium": 0, "High": 0}
if "history" not in st.session_state:
    st.session_state["history"] = []

# ---------------------------------------------------------------------------
# Page header
# ---------------------------------------------------------------------------
st.title("🛡️ PhishGuard")
st.markdown(
    """
    **Explainable Phishing Email Risk Analyzer** — an educational tool that
    inspects email content for common phishing indicators and explains its
    reasoning.

    > ⚠️ **Disclaimer:** This tool is for learning purposes only. It can produce
    > false positives and false negatives, and does not replace professional
    > security software. No email content is stored or transmitted.
    """
)

st.divider()

# ---------------------------------------------------------------------------
# Dashboard summary cards
# ---------------------------------------------------------------------------
st.subheader("📈 Session Dashboard")
total = st.session_state["total_analyzed"]
rc    = st.session_state["risk_counts"]
col1, col2, col3, col4 = st.columns(4)
col1.metric("Emails Analysed", total)
col2.metric("🟢 Low",    rc["Low"])
col3.metric("🟡 Medium", rc["Medium"])
col4.metric("🔴 High",   rc["High"])

st.divider()

# =============================================================================
# TABS — three input modes
# =============================================================================
tab_manual, tab_eml, tab_bulk = st.tabs([
    "✏️ Manual Entry",
    "📎 Upload .eml File",
    "📂 Bulk Upload",
])


# ---------------------------------------------------------------------------
# Shared helper — render analysis results for a single email
# ---------------------------------------------------------------------------
def _render_result(sender: str, subject: str, result: dict,
                   header_warnings: list[str] | None = None) -> None:
    """
    Render the risk banner, header warnings, indicator cards, weight chart,
    and CSV download for a single analysis result dict.
    """
    score      = result["score"]
    risk_level = result["risk_level"]
    findings   = result["findings"]
    bonus      = result["bonus"]

    # Update session counters
    st.session_state["total_analyzed"] += 1
    st.session_state["risk_counts"][risk_level] += 1
    st.session_state["history"].append({
        "#":          st.session_state["total_analyzed"],
        "Sender":     sender[:40] or "(empty)",
        "Subject":    subject[:45] or "(empty)",
        "Score":      score,
        "Risk Level": risk_level,
        "Indicators": len(findings),
    })

    # Risk banner
    RISK_STYLE = {
        "Low":    ("🟢", "success"),
        "Medium": ("🟡", "warning"),
        "High":   ("🔴", "error"),
    }
    icon, alert_type = RISK_STYLE[risk_level]
    msg = f"{icon} **Risk Level: {risk_level}** — Indicative score: {score} / 100"
    if alert_type == "success":
        st.success(msg)
    elif alert_type == "warning":
        st.warning(msg)
    else:
        st.error(msg)

    # Score metadata
    score_line = (
        f"**Scoring thresholds:** Low = 0–29 · Medium = 30–59 · High = 60–100  \n"
        f"**Indicators triggered:** {len(findings)} of {len(RULES)}"
    )
    if bonus:
        score_line += f"  \n**Co-occurrence bonus:** +{bonus} pts (3+ indicators fired)"
    st.markdown(score_line)

    # Header warnings (from .eml parsing — informational only, no score impact)
    if header_warnings:
        st.markdown("---")
        st.markdown("### 📋 Email Header Warnings")
        st.caption(
            "These observations come from the email's technical headers. "
            "They are informational — they do not affect the risk score but "
            "are strong signals when present."
        )
        for w in header_warnings:
            st.warning(w)

    # Findings breakdown
    if findings:
        st.markdown("---")
        st.markdown("### 🔎 Detected Indicators")
        for idx, f in enumerate(findings, start=1):
            with st.expander(
                f"{idx}. {f['indicator']}  (+{f['weight']} pts)", expanded=True
            ):
                st.markdown(f"**What was detected:**  \n{f['detail']}")
                st.markdown(f"**Recommended action:**  \n{f['advice']}")
    else:
        st.markdown("---")
        st.info(
            "✅ No suspicious indicators were found by the current rule set.  \n"
            "This does not guarantee the email is safe — always apply critical "
            "judgement and verify through official channels when in doubt."
        )

    # Weight chart
    if findings:
        st.markdown("---")
        st.markdown("### 📊 Indicator Weight Breakdown")
        st.caption("Each bar shows how many risk points that indicator contributed.")
        chart_df = pd.DataFrame({
            "Indicator":   [f["indicator"] for f in findings],
            "Risk Points": [f["weight"] for f in findings],
        }).set_index("Indicator")
        st.bar_chart(chart_df)

    # CSV download
    st.markdown("---")
    csv_data = build_csv_report(sender, subject, result)
    st.download_button(
        label="⬇️ Download Report (CSV)",
        data=csv_data,
        file_name="phishguard_report.csv",
        mime="text/csv",
        help="Download a CSV summary of this analysis result.",
    )

    st.caption(
        "⚠️ Results are indicative only. This tool may miss real phishing emails "
        "(false negatives) and flag legitimate emails (false positives). "
        "It does not replace professional email security tools."
    )
    st.caption("🔒 Privacy: this content has not been stored, logged, or transmitted.")


# =============================================================================
# TAB 1 — Manual Entry
# =============================================================================
with tab_manual:
    st.subheader("📂 Load a Sample Email")
    selected_sample = st.selectbox(
        "Choose a sample to pre-fill the form:",
        options=list(SAMPLE_EMAILS.keys()),
        key="sample_selector",
    )
    sample_data = SAMPLE_EMAILS[selected_sample]

    st.subheader("📧 Email Details")
    sender = st.text_input(
        "Sender Address",
        value=sample_data["sender"],
        placeholder='e.g. support@example.com  or  "Brand" <alert@evil.com>',
        help='The From: field. Accepts "Display Name <address>" format.',
        key="manual_sender",
    )
    subject = st.text_input(
        "Subject Line",
        value=sample_data["subject"],
        placeholder="e.g. Your account needs attention",
        key="manual_subject",
    )
    body = st.text_area(
        "Email Body",
        value=sample_data["body"],
        placeholder="Paste the full text of the email here (plain text or HTML)...",
        height=220,
        help="HTML tags are stripped before analysis.",
        key="manual_body",
    )

    st.divider()
    if st.button("🔍 Analyze Email", type="primary", use_container_width=True,
                 key="btn_manual"):
        if not sender.strip() and not subject.strip() and not body.strip():
            st.warning("Please fill in at least one field before analyzing.")
        else:
            errors = validate_inputs(sender.strip(), subject.strip(), body.strip())
            if errors:
                for err in errors:
                    st.error(f"❌ {err}")
            else:
                st.subheader("📊 Analysis Results")
                result = analyze_email(sender.strip(), subject.strip(), body.strip())
                _render_result(sender.strip(), subject.strip(), result)


# =============================================================================
# TAB 2 — Upload .eml File  (Future #1 + #2)
# =============================================================================
with tab_eml:
    st.subheader("📎 Upload an .eml File")
    st.markdown(
        "Upload a raw email file (`.eml` format). PhishGuard will extract the "
        "sender, subject, and body automatically, and additionally check the "
        "email headers for authentication warnings (Reply-To mismatch, "
        "SPF/DKIM/DMARC failures)."
    )
    st.caption(
        "🔒 The file is parsed in memory only. Nothing is written to disk or "
        "transmitted. The file is discarded after analysis."
    )

    uploaded_eml = st.file_uploader(
        "Choose an .eml file",
        type=["eml"],
        key="eml_uploader",
        help="Standard RFC 5322 email files exported from most email clients.",
    )

    if uploaded_eml is not None:
        if st.button("🔍 Analyze .eml File", type="primary",
                     use_container_width=True, key="btn_eml"):
            raw_bytes = uploaded_eml.read()
            try:
                parsed = parse_eml(raw_bytes)
            except Exception as exc:
                st.error(f"❌ Could not parse the .eml file: {exc}")
            else:
                sender_eml  = parsed["sender"]
                subject_eml = parsed["subject"]
                body_eml    = parsed["body"]
                header_warnings = parsed["header_warnings"]

                st.markdown("**Extracted fields:**")
                st.markdown(f"- **From:** `{sender_eml or '(empty)'}`")
                st.markdown(f"- **Subject:** `{subject_eml or '(empty)'}`")
                st.markdown(f"- **Body length:** {len(body_eml)} characters")

                errors = validate_inputs(sender_eml, subject_eml, body_eml)
                if errors:
                    for err in errors:
                        st.error(f"❌ {err}")
                else:
                    st.subheader("📊 Analysis Results")
                    result = analyze_email(sender_eml, subject_eml, body_eml)
                    _render_result(
                        sender_eml, subject_eml, result,
                        header_warnings=header_warnings,
                    )


# =============================================================================
# TAB 3 — Bulk Upload  (Future #7)
# =============================================================================
with tab_bulk:
    st.subheader("📂 Bulk Email Analysis")
    st.markdown(
        "Upload multiple `.eml` files at once. PhishGuard will analyse each one "
        "and produce a summary table you can download as CSV."
    )
    st.caption(
        "🔒 All files are parsed in memory only. Nothing is written to disk or "
        "transmitted. Files are discarded after analysis."
    )

    uploaded_bulk = st.file_uploader(
        "Choose one or more .eml files",
        type=["eml"],
        accept_multiple_files=True,
        key="bulk_uploader",
        help="Hold Ctrl / Cmd to select multiple files.",
    )

    if uploaded_bulk:
        st.markdown(f"**{len(uploaded_bulk)} file(s) selected.**")
        if st.button("🔍 Analyse All", type="primary",
                     use_container_width=True, key="btn_bulk"):
            bulk_rows: list[dict] = []
            errors_encountered: list[str] = []

            progress = st.progress(0, text="Analysing…")
            for i, f in enumerate(uploaded_bulk):
                try:
                    parsed = parse_eml(f.read())
                    result = analyze_email(
                        parsed["sender"], parsed["subject"], parsed["body"]
                    )
                    # Update global session counters
                    st.session_state["total_analyzed"] += 1
                    st.session_state["risk_counts"][result["risk_level"]] += 1
                    st.session_state["history"].append({
                        "#":          st.session_state["total_analyzed"],
                        "Sender":     parsed["sender"][:40] or "(empty)",
                        "Subject":    parsed["subject"][:45] or "(empty)",
                        "Score":      result["score"],
                        "Risk Level": result["risk_level"],
                        "Indicators": len(result["findings"]),
                    })
                    bulk_rows.append({
                        "File":         f.name,
                        "Sender":       parsed["sender"][:50] or "(empty)",
                        "Subject":      parsed["subject"][:55] or "(empty)",
                        "Score":        result["score"],
                        "Risk Level":   result["risk_level"],
                        "Indicators":   len(result["findings"]),
                        "Header Warns": len(parsed["header_warnings"]),
                    })
                except Exception as exc:
                    errors_encountered.append(f"{f.name}: {exc}")

                progress.progress(
                    (i + 1) / len(uploaded_bulk),
                    text=f"Analysed {i + 1} / {len(uploaded_bulk)}"
                )

            progress.empty()

            if errors_encountered:
                for err in errors_encountered:
                    st.error(f"❌ {err}")

            if bulk_rows:
                st.subheader("📊 Bulk Results")
                bulk_df = pd.DataFrame(bulk_rows)
                st.dataframe(bulk_df, use_container_width=True, hide_index=True)

                # Bulk CSV download
                import io as _io, csv as _csv
                out = _io.StringIO()
                writer = _csv.DictWriter(out, fieldnames=bulk_df.columns.tolist())
                writer.writeheader()
                writer.writerows(bulk_rows)
                st.download_button(
                    label="⬇️ Download Bulk Results (CSV)",
                    data=out.getvalue(),
                    file_name="phishguard_bulk_results.csv",
                    mime="text/csv",
                )

                # Quick distribution chart
                risk_counts_bulk = bulk_df["Risk Level"].value_counts()
                st.markdown("#### Risk Level Distribution (this batch)")
                dist_df = pd.DataFrame({
                    "Count": [
                        risk_counts_bulk.get("Low", 0),
                        risk_counts_bulk.get("Medium", 0),
                        risk_counts_bulk.get("High", 0),
                    ]
                }, index=["🟢 Low", "🟡 Medium", "🔴 High"])
                st.bar_chart(dist_df)

                st.caption("🔒 No file content has been stored, logged, or transmitted.")


# =============================================================================
# SESSION HISTORY (all tabs)
# =============================================================================
if st.session_state["history"]:
    st.divider()
    st.subheader("🗂️ Session History")
    st.info(
        "💡 Session data is held in memory only. "
        "Refreshing or closing this tab will clear all history. "
        "Use the **Download Report** buttons above to save individual results.",
        icon="ℹ️",
    )
    history_df = pd.DataFrame(st.session_state["history"])
    st.dataframe(history_df, use_container_width=True, hide_index=True)

    if st.session_state["total_analyzed"] > 1:
        st.markdown("#### Risk Level Distribution (Session)")
        dist_df = pd.DataFrame({
            "Risk Level": ["🟢 Low", "🟡 Medium", "🔴 High"],
            "Count": [
                st.session_state["risk_counts"]["Low"],
                st.session_state["risk_counts"]["Medium"],
                st.session_state["risk_counts"]["High"],
            ],
        }).set_index("Risk Level")
        st.bar_chart(dist_df)
