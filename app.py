"""app.py - SiteSage AI: the Streamlit web interface.  Run with:  streamlit run app.py"""
import html

import streamlit as st

from auditor import (AuditError, analyze, export_df, fetch_page, headings_df,
                     images_df, links_df, score_color, checks_df)
from report import build_pdf

st.set_page_config(page_title="SiteSage AI", page_icon="🔍", layout="wide")

st.markdown("""
<style>
.block-container {padding-top: 2rem; max-width: 1200px;}
.card {background:#fff; border:1px solid #E2E8F0; border-radius:14px; padding:18px 20px;
       box-shadow:0 1px 3px rgba(15,23,42,.06); height:100%;}
.m-label {font-size:.78rem; color:#64748B; text-transform:uppercase; letter-spacing:.05em; font-weight:600;}
.m-value {font-size:2rem; font-weight:700; line-height:1.2;}
.m-sub {font-size:.82rem; color:#64748B;}
.ring {width:120px; height:120px; border-radius:50%; display:flex; align-items:center; justify-content:center;}
.ring-in {width:92px; height:92px; border-radius:50%; background:#fff; display:flex; flex-direction:column;
          align-items:center; justify-content:center; font-size:1.9rem; font-weight:700; line-height:1;}
.ring-in small {font-size:.7rem; color:#64748B; font-weight:500;}
.score-wrap {display:flex; align-items:center; gap:18px;}
.badge {display:inline-block; min-width:78px; text-align:center; padding:3px 10px; border-radius:999px;
        font-size:.72rem; font-weight:700; color:#fff;}
.b-pass {background:#16A34A;} .b-warning {background:#D97706;} .b-fail {background:#DC2626;} .b-info {background:#2563EB;}
.row {display:flex; gap:14px; align-items:flex-start; background:#fff; border:1px solid #E2E8F0;
      border-radius:12px; padding:12px 16px; margin-bottom:10px;}
.row .name {font-weight:600;} .row .text {color:#475569; font-size:.9rem;} .row .pts {margin-left:auto; color:#64748B; font-size:.85rem; white-space:nowrap;}
.rec {border-left:4px solid #4F46E5; background:#fff; border-radius:8px; padding:12px 16px; margin-bottom:10px; border-top:1px solid #E2E8F0; border-right:1px solid #E2E8F0; border-bottom:1px solid #E2E8F0;}
</style>
""", unsafe_allow_html=True)

esc = html.escape


def card(label, value, sub="", color="#0F172A"):
    return (f'<div class="card"><div class="m-label">{esc(label)}</div>'
            f'<div class="m-value" style="color:{color}">{esc(str(value))}</div>'
            f'<div class="m-sub">{esc(sub)}</div></div>')


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.markdown("## 🔍 SiteSage AI")
    st.caption("Website SEO audit assistant")
    with st.form("audit_form"):
        url_input = st.text_input("Website URL", placeholder="https://example.com")
        submitted = st.form_submit_button("Run audit", type="primary")
    st.divider()
    st.markdown("**Checks performed**")
    st.markdown("- HTTPS\n- Page title\n- Meta description\n- H1 and heading structure\n"
                "- Image alt text\n- Internal and external links")
    st.markdown("**Not measured**")
    st.markdown("- Google rankings\n- Traffic\n- Core Web Vitals / speed scores\n- Backlinks\n- JavaScript-added content")
    st.caption("Recommendations come from built-in rules, not a paid AI API.")

# ---------------------------------------------------------------- run audit
if submitted:
    st.session_state.pop("result", None)
    st.session_state.pop("error", None)
    try:
        with st.spinner("Fetching and analysing the page..."):
            st.session_state["result"] = analyze(fetch_page(url_input), url_input)
    except AuditError as exc:
        st.session_state["error"] = str(exc)
    except Exception as exc:  # last-resort safety net
        print("Unexpected error:", repr(exc))
        st.session_state["error"] = "Something unexpected went wrong while auditing that page."

# ---------------------------------------------------------------- main area
st.title("SEO Audit Dashboard")

if "error" in st.session_state:
    st.error(st.session_state["error"])

result = st.session_state.get("result")

if result is None:
    if "error" not in st.session_state:
        st.markdown(
            '<div class="card"><b>Welcome to SiteSage AI.</b><br>Enter a public website URL in the sidebar '
            'and press <b>Run audit</b>. The tool downloads that page, checks its on-page SEO basics and '
            'explains your score.</div>', unsafe_allow_html=True)
    st.stop()

st.caption(f"Audited: {result.final_url}  |  {result.audited_at:%d %b %Y, %H:%M}")
if result.truncated:
    st.warning("The page was larger than 2 MB, so only the first 2 MB was analysed.")

col = score_color(result.score)
c1, c2, c3, c4 = st.columns([1.5, 1, 1, 1])
c1.markdown(
    f'<div class="card"><div class="score-wrap"><div class="ring" style="background:conic-gradient({col} {result.score * 3.6}deg,#E5E7EB 0deg)">'
    f'<div class="ring-in">{result.score}<small>/ 100</small></div></div>'
    f'<div><div class="m-label">SEO health score</div><div class="m-value" style="color:{col}">{esc(result.grade)}</div>'
    f'<div class="m-sub">Based on the checks performed</div></div></div></div>', unsafe_allow_html=True)
c2.markdown(card("Passed", result.count("pass"), "checks", "#16A34A"), unsafe_allow_html=True)
c3.markdown(card("Warnings", result.count("warning"), "checks", "#D97706"), unsafe_allow_html=True)
c4.markdown(card("Failed", result.count("fail"), "checks", "#DC2626"), unsafe_allow_html=True)

st.write("")
d1, d2, d3, d4 = st.columns(4)
d1.markdown(card("HTTP status", result.status_code, "final response"), unsafe_allow_html=True)
d2.markdown(card("Fetch time", f"{result.seconds:.2f}s", "download time, not a speed score"), unsafe_allow_html=True)
d3.markdown(card("HTML size", f"{result.size_kb:.0f} KB", "downloaded document only"), unsafe_allow_html=True)
d4.markdown(card("Links found", len(result.internal_links) + len(result.external_links),
                 f"{len(result.internal_links)} internal, {len(result.external_links)} external"), unsafe_allow_html=True)
st.write("")

tab_checks, tab_recs, tab_data, tab_export = st.tabs(["Audit checks", "Recommendations", "Page data", "Export"])

with tab_checks:
    st.caption("Score = points earned / points available across scored checks. Pass = full points, warning = half, fail = zero. Info checks are not scored.")
    for c in result.checks:
        pts = "not scored" if c.status == "info" else f"{c.earned:g} / {c.weight} pts"
        st.markdown(
            f'<div class="row"><span class="badge b-{c.status}">{c.status.upper()}</span>'
            f'<div><div class="name">{esc(c.name)} <span style="color:#94A3B8;font-weight:400">· {esc(c.category)}</span></div>'
            f'<div class="text">{esc(c.finding)}</div></div><div class="pts">{pts}</div></div>', unsafe_allow_html=True)

with tab_recs:
    todo = [c for c in result.checks if c.status == "fail"] + [c for c in result.checks if c.status == "warning"]
    if not todo:
        st.success("All scored checks passed. No fixes needed.")
    for c in todo:
        st.markdown(
            f'<div class="rec"><span class="badge b-{c.status}">{c.status.upper()}</span> '
            f'<b>{esc(c.name)}</b><div class="text" style="margin-top:6px">{esc(c.recommendation)}</div></div>',
            unsafe_allow_html=True)

with tab_data:
    st.subheader("Title and meta description")
    st.write(f"**Title:** {result.title or '(none)'}")
    st.write(f"**Meta description:** {result.meta_description or '(none)'}")
    st.subheader("Headings")
    st.dataframe(headings_df(result), hide_index=True)
    st.subheader("Images")
    st.dataframe(images_df(result), hide_index=True)
    st.subheader("Internal links")
    st.dataframe(links_df(result.internal_links), hide_index=True)
    st.subheader("External links")
    st.dataframe(links_df(result.external_links), hide_index=True)

with tab_export:
    st.write("Download this audit to share it or keep a record.")
    e1, e2 = st.columns(2)
    e1.download_button("Download PDF report", data=build_pdf(result), file_name="sitesage-audit.pdf", mime="application/pdf")
    e2.download_button("Download CSV", data=export_df(result).to_csv(index=False).encode("utf-8-sig"),
                       file_name="sitesage-audit.csv", mime="text/csv")
