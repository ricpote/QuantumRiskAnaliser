"""QuantumTrace dashboard (Streamlit).  Run:  streamlit run app/streamlit_app.py"""
from __future__ import annotations

import copy
import io
import json
import os
import sys
import tempfile
import zipfile

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from quantumtrace.cli import collect  # noqa: E402
from quantumtrace.export import cyclonedx, sarif  # noqa: E402
from quantumtrace.score import asset_label, summarize  # noqa: E402

TIER_COLORS = {"critical": "#D7263D", "medium": "#F4A261", "safe": "#2A9D8F", "unencrypted": "#5B2A86"}
TIER_ORDER = ["unencrypted", "critical", "medium", "safe"]

st.set_page_config(page_title="QuantumTrace", page_icon="🛰️", layout="wide")
st.markdown("""
<style>
.block-container {padding-top: 1.5rem;}
.qt-kpi {border-radius: 12px; padding: 14px 16px; background: rgba(127,127,127,.08); border: 1px solid rgba(127,127,127,.18);}
.qt-kpi .v {font-size: 1.9rem; font-weight: 700; line-height: 1.1}
.qt-kpi .l {font-size: .8rem; opacity: .75; text-transform: uppercase; letter-spacing: .04em}
.qt-pill {display:inline-block; padding:2px 8px; border-radius:999px; color:white; font-size:.75rem; font-weight:600}
</style>""", unsafe_allow_html=True)


def pill(tier):
    return f'<span class="qt-pill" style="background:{TIER_COLORS.get(tier, "#888")}">{tier}</span>'


@st.cache_data(show_spinner="Scanning…")
def run_scan(paths: tuple, now: str | None):
    if now:
        os.environ["QT_NOW"] = now
    cwd = os.getcwd()
    os.chdir(ROOT)
    try:
        fs = collect(list(paths))
    finally:
        os.chdir(cwd)
    return [f.to_dict() for f in fs]


def to_findings(dicts):
    from quantumtrace.schema import Finding
    return [Finding.from_dict(d) for d in dicts]


# ------------------------------------------------------------------ sidebar
with st.sidebar:
    st.markdown("## 🛰️ QuantumTrace")
    st.caption("Cryptographic inventory · CBOM · post-quantum readiness")
    mode = st.radio("Input", ["Official challenge samples", "Upload files"], index=0)
    paths = ("samples/official",)
    if mode == "Upload files":
        ups = st.file_uploader("PCAP, AWS JSON exports, source code or a .zip", accept_multiple_files=True)
        if ups:
            tmp = tempfile.mkdtemp(prefix="qt_")
            for u in ups:
                data = u.getvalue()
                if u.name.endswith(".zip"):
                    zipfile.ZipFile(io.BytesIO(data)).extractall(tmp)
                else:
                    open(os.path.join(tmp, u.name), "wb").write(data)
            paths = (tmp,)
    now = st.text_input("Evaluation date (UTC)", "2026-10-10T12:00:00Z", help="Used for certificate expiry / KMS deletion countdowns")
    st.divider()
    st.markdown("**Risk model**")
    st.caption("100 = Shor + Harvest-Now-Decrypt-Later or cleartext · 90 = Shor long-lived signature · 75 = other Shor · 40 = Grover-weakened · 0 = quantum-safe. "
               "QRS = mean over sources of (100 − mean asset risk).")

findings = to_findings(run_scan(paths, now))
S = summarize(findings)

# ------------------------------------------------------------------ header + KPIs
st.title("Quantum Readiness Report")
st.caption(f"Scanned **{S['assets']} assets** · **{S['findings']} findings** from " + ", ".join(S["sources"].keys()))
k = st.columns(6)
net = S["network"]
kpis = [
    (f"{S['quantum_readiness_score']}", f"Quantum Readiness Score · grade {S['grade']}"),
    (f"{net['pq_protected']}/{net['endpoints']}", "network endpoints PQ-protected"),
    (f"{net['hndl_exposed']}", "endpoints exposed to HNDL"),
    (f"{net['plaintext']}", "cleartext endpoints"),
    (f"{S['tiers'].get('critical', 0)}", "Shor-vulnerable findings"),
    (f"{S['classical'].get('broken', 0)}", "classically broken"),
]
for col, (v, l) in zip(k, kpis):
    col.markdown(f'<div class="qt-kpi"><div class="v">{v}</div><div class="l">{l}</div></div>', unsafe_allow_html=True)
st.write("")

TAB_NAMES = ["Overview", "Live probe", "Network", "Code", "Cloud", "Migration plan", "CBOM & exports", "Accuracy", "Explain"]
T = dict(zip(TAB_NAMES, st.tabs(TAB_NAMES)))

# ------------------------------------------------------------------ overview
with T["Overview"]:
    c1, c2, c3 = st.columns([1.1, 1, 1.4])
    with c1:
        g = go.Figure(go.Indicator(mode="gauge+number", value=S["quantum_readiness_score"] or 0,
                                   gauge=dict(axis=dict(range=[0, 100]), bar=dict(color="#264653"),
                                              steps=[dict(range=[0, 40], color="#f8d7da"), dict(range=[40, 70], color="#fde8c8"), dict(range=[70, 100], color="#d4f1ec")]),
                                   title=dict(text="Quantum Readiness Score")))
        g.update_layout(height=260, margin=dict(l=35, r=45, t=50, b=10))
        st.plotly_chart(g, use_container_width=True)
    with c2:
        dt = pd.DataFrame([(t, n) for t, n in S["tiers"].items()], columns=["tier", "findings"])
        fig = px.pie(dt, names="tier", values="findings", hole=.55, color="tier", color_discrete_map=TIER_COLORS, title="Findings by quantum risk tier")
        fig.update_layout(height=260, margin=dict(l=10, r=10, t=50, b=10), legend=dict(orientation="h"))
        st.plotly_chart(fig, use_container_width=True)
    with c3:
        ds = pd.DataFrame([dict(source=s, score=d["score"], assets=d["assets"]) for s, d in S["sources"].items()])
        fig = px.bar(ds, x="source", y="score", text="score", range_y=[0, 100], title="Readiness by source (0 = fully exposed)", color_discrete_sequence=["#264653"])
        fig.update_layout(height=260, margin=dict(l=10, r=10, t=50, b=10))
        st.plotly_chart(fig, use_container_width=True)
    st.subheader("Highest-risk assets")
    st.dataframe(pd.DataFrame([dict(asset=a["label"], source=a["source"], worst_tier=a["worst_tier"], risk=a["risk"], HNDL=a["hndl"],
                                    classical_broken=a["classical_broken"]) for a in S["top_assets"]]), use_container_width=True, hide_index=True)

# ------------------------------------------------------------------ live probe
with T["Live probe"]:
    from quantumtrace.classify import classify_all
    from quantumtrace.cli import verdict
    from quantumtrace.kb import tls as TLSKB
    st.subheader("Live TLS probe")
    st.caption("Hand-built ClientHellos: one per key-exchange group (ML-KEM hybrids, pure ML-KEM, ECDH, FFDHE), per version and per cipher. "
               "For TLS 1.3 we decrypt our own handshake (ML-KEM decapsulation + key schedule) to read the certificate and CertificateVerify. "
               "STARTTLS is automatic on 25/587/143/110/5432.")
    c1, c2, c3 = st.columns([4, 1.2, 1])
    targets_txt = c1.text_input("Targets (host[:port], comma separated)", os.environ.get("QT_PROBE_TARGETS", "127.0.0.1:8443, 127.0.0.1:8446, 127.0.0.1:8445"))
    deep = c2.toggle("Deep (auth schemes)", value=False)
    run = c3.button("Probe", type="primary", use_container_width=True)
    if run:
        from quantumtrace.ingest import probe as P
        tg = [t.strip() for t in targets_txt.split(",") if t.strip()]
        with st.spinner(f"Probing {len(tg)} endpoint(s)…"):
            pf, reps = P.ingest(tg, deep=deep)
        st.session_state["probe"] = ([f.to_dict() for f in classify_all(pf)], reps)
    if "probe" in st.session_state:
        pdicts, reps = st.session_state["probe"]
        pfind = to_findings(pdicts)
        for r in reps:
            color, text = verdict(r)
            border = {"green": TIER_COLORS["safe"], "red": TIER_COLORS["critical"]}.get(color, "#888")
            st.markdown(f'<div class="qt-kpi" style="border-left:6px solid {border}; margin-top:10px"><div class="l">{r["target"]}'
                        f'{" · STARTTLS " + r["starttls"] if r.get("starttls") else ""} · {r.get("connections", 0)} handshakes · {r.get("duration_s", 0)} s</div>'
                        f'<div style="font-size:1.15rem;font-weight:650;margin-top:4px">{text}</div></div>', unsafe_allow_html=True)
            m = r.get("modern") or {}
            k1, k2, k3 = st.columns(3)
            k1.metric("Modern client key exchange", m.get("group_name") or (m.get("alert") or "—"))
            k2.metric("Negotiated", f"{m.get('version') or '—'}", m.get("cipher") or "")
            k3.markdown(f'<div style="font-size:.875rem">CertificateVerify</div><div style="font-size:1.35rem;margin-top:.35rem">{m.get("cert_verify_name") or "—"}</div>',
                        unsafe_allow_html=True)
            if r.get("groups"):
                pills = []
                for gname, gv in r["groups"].items():
                    pq = TLSKB.GROUPS.get(gv["code"], {}).get("pq")
                    col = (TIER_COLORS["safe"] if pq else TIER_COLORS["critical"]) if gv["supported"] else "#bbb"
                    pills.append(f'<span class="qt-pill" style="background:{col};margin:2px">{"✓" if gv["supported"] else "✗"} {gname}</span>')
                st.markdown("**Key-exchange groups** " + " ".join(pills), unsafe_allow_html=True)
            vp = " ".join(f'<span class="qt-pill" style="background:{(TIER_COLORS["medium"] if v in ("TLS 1.0", "TLS 1.1", "SSL 3.0") else "#264653") if ok else "#bbb"};margin:2px">{"✓" if ok else "✗"} {v}</span>'
                          for v, ok in r["versions"].items())
            st.markdown("**Protocol versions** " + vp, unsafe_allow_html=True)
            with st.expander("Details: ciphers, certificate chain, findings"):
                if r.get("tls13_ciphers"):
                    st.write("TLS 1.3:", ", ".join(r["tls13_ciphers"]))
                if r.get("tls12_ciphers"):
                    st.write("TLS 1.2 (server preference order):", ", ".join(c["name"] for c in r["tls12_ciphers"]))
                if r.get("certs"):
                    st.dataframe(pd.DataFrame([dict(subject=c.get("subject"), issuer=c.get("issuer"), key=f"{c.get('algorithm')}-{c.get('key_bits') or c.get('curve')}",
                                                    signature_hash=c.get("sig_hash"), not_after=(c.get("not_after") or "")[:10]) for c in r["certs"]]), hide_index=True, use_container_width=True)
                mine = [f for f in pfind if f.location.get("probe") == r["target"]]
                st.dataframe(pd.DataFrame([dict(category=f.category, algorithm=f.display_name, tier=f.risk_tier, classical=f.classical_status, flags=", ".join(f.flags), evidence=f.evidence) for f in mine]),
                             hide_index=True, use_container_width=True)
        pbom = cyclonedx.build(pfind, summarize(pfind), target="live probe")
        st.download_button("⬇ Probe CBOM (CycloneDX 1.6)", json.dumps(pbom, indent=2), "probe_cbom.cdx.json", "application/json")

# ------------------------------------------------------------------ network
with T["Network"]:
    nf = [f for f in findings if f.source == "network"]
    if not nf:
        st.info("No network capture in this scan.")
    else:
        rows = {}
        for f in nf:
            key = (f.asset["host"], f.asset["port"], f.location.get("stream"))
            r = rows.setdefault(key, dict(host=f.asset["host"], port=f.asset["port"], service=f.asset.get("service"), protocol="", key_exchange="", kex_tier="",
                                          authentication="", cipher="", worst="safe", flags=set(), stream=f.location.get("stream")))
            if f.category == "protocol":
                r["protocol"] = f.display_name
            if f.category in ("key-exchange", "transport"):
                r["key_exchange"], r["kex_tier"] = f.display_name, f.risk_tier
            if f.category == "authentication":
                r["authentication"] = f.display_name
            if f.category == "encryption":
                r["cipher"] = f.display_name
            if TIER_ORDER.index(f.risk_tier) < TIER_ORDER.index(r["worst"]):
                r["worst"] = f.risk_tier
            r["flags"].update(f.flags)
        df = pd.DataFrame([dict(r, flags=", ".join(sorted(r["flags"]))) for r in rows.values()])
        c1, c2 = st.columns([1, 2])
        with c1:
            agg = df.groupby(["key_exchange", "kex_tier"]).size().reset_index(name="sessions")
            fig = px.bar(agg, x="sessions", y="key_exchange", color="kex_tier", orientation="h", color_discrete_map=TIER_COLORS, title="Key exchange (decides HNDL exposure)")
            fig.update_layout(height=320, margin=dict(l=10, r=10, t=50, b=10), yaxis_title=None)
            st.plotly_chart(fig, use_container_width=True)
        with c2:
            svc = st.multiselect("Service", sorted(df.service.unique()), default=[])
            view = df[df.service.isin(svc)] if svc else df
            st.dataframe(view.drop(columns=["stream"]).sort_values(["kex_tier", "service", "host"]), use_container_width=True, hide_index=True, height=320)
        st.caption("TLS 1.3 certificates are encrypted on the wire: authentication is inferred from the client's offered signature_algorithms (the server must pick one of them).")
        pick = st.selectbox("Inspect a session", [f"{r['host']}:{r['port']} (stream {r['stream']})" for r in rows.values()])
        if pick:
            stream = int(pick.split("stream ")[1].rstrip(")"))
            for f in [x for x in nf if x.location.get("stream") == stream]:
                with st.expander(f"{f.category}: {f.display_name} — {f.risk_tier} / classical {f.classical_status}"):
                    st.markdown(f"**Evidence** (frame {f.location.get('frame')}): {f.evidence}")
                    for w in f.rationale:
                        st.markdown(f"- {w}")
                    if f.replacement:
                        st.success(f"→ {f.replacement['algorithm']} ({f.replacement['standard']}): {f.replacement['how']}")
                    if f.context.get("offered"):
                        st.json(f.context["offered"], expanded=False)

# ------------------------------------------------------------------ code
with T["Code"]:
    cf = [f for f in findings if f.source == "code" and f.algorithm not in ("LIBRARY",)]
    if not cf:
        st.info("No source code in this scan.")
    else:
        df = pd.DataFrame([dict(file=f.location.get("file"), line=f.location.get("line"), category=f.category, algorithm=f.display_name, tier=f.risk_tier,
                                classical=f.classical_status, flags=", ".join(f.flags), confidence=f.confidence, snippet=f.location.get("snippet")) for f in cf])
        only = st.toggle("Only risky findings", value=True)
        if only:
            df = df[(df.tier != "safe") | (df.classical.isin(["broken", "deprecated"]))]
        st.dataframe(df.sort_values(["file", "line"]), use_container_width=True, hide_index=True, height=380)
        files = sorted({f.location.get("file") for f in cf})
        fsel = st.selectbox("Open file", files)
        if fsel:
            path = os.path.join(ROOT, fsel) if not os.path.isabs(fsel) else fsel
            lines = {f.location.get("line"): f for f in cf if f.location.get("file") == fsel}
            try:
                src = open(path, encoding="utf-8", errors="replace").read().splitlines()
                annotated = "\n".join((f"{i:>3} ▶ " if i in lines else f"{i:>3}   ") + l for i, l in enumerate(src, 1))
                st.code(annotated, language=None)
            except OSError:
                pass
            for ln, f in sorted(lines.items()):
                st.markdown(f"**L{ln}** {pill(f.risk_tier)} `{f.display_name}` — {f.evidence}", unsafe_allow_html=True)

# ------------------------------------------------------------------ cloud
with T["Cloud"]:
    cl = [f for f in findings if f.source == "cloud"]
    if not cl:
        st.info("No cloud exports in this scan.")
    else:
        kms = [f for f in cl if f.asset.get("kind") == "aws-kms-key"]
        if kms:
            st.subheader("KMS keys")
            st.dataframe(pd.DataFrame([dict(alias=f.asset.get("alias"), usage=f.context.get("key_usage"), algorithm=f.display_name, tier=f.risk_tier, HNDL=f.hndl,
                                            state=f.context.get("key_state"), origin=f.context.get("origin"), rotation=f.context.get("rotation"),
                                            age_years=f.context.get("age_years"), flags=", ".join(f.flags)) for f in kms]), use_container_width=True, hide_index=True)
        lst = [f for f in cl if f.asset.get("kind") == "aws-elb-listener"]
        if lst:
            st.subheader("Load balancer listeners")
            rows = {}
            for f in lst:
                key = f"{f.asset['load_balancer']}:{f.asset['port']}"
                r = rows.setdefault(key, dict(listener=key, scheme=f.asset.get("scheme"), policy=f.context.get("ssl_policy", "— (no TLS)"), lowest_tls="", RSA_kex=False, PQ=False, worst="safe"))
                if f.category == "protocol":
                    r["lowest_tls"] = f.display_name
                if f.category == "key-exchange" and f.algorithm == "RSA":
                    r["RSA_kex"] = True
                if f.category == "key-exchange" and f.quantum_threat == "none":
                    r["PQ"] = True
                if TIER_ORDER.index(f.risk_tier) < TIER_ORDER.index(r["worst"]):
                    r["worst"] = f.risk_tier
            st.dataframe(pd.DataFrame(rows.values()), use_container_width=True, hide_index=True)
            st.info("Fix: `aws elbv2 modify-listener --ssl-policy ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` (AWS-recommended hybrid ML-KEM policy).")
        acm = [f for f in cl if f.asset.get("kind") == "aws-acm-certificate"]
        if acm:
            st.subheader("Certificates")
            st.dataframe(pd.DataFrame([dict(domain=f.asset.get("domain"), algorithm=f.display_name, not_after=(f.context.get("not_after") or "")[:10],
                                            classical=f.classical_status, flags=", ".join(f.flags)) for f in acm]), use_container_width=True, hide_index=True)

# ------------------------------------------------------------------ migration plan + what-if
with T["Migration plan"]:
    st.subheader("Prioritised migration plan")
    st.caption("P0 = confidentiality exposed to Harvest-Now-Decrypt-Later or no encryption · P1 = Shor-vulnerable signatures / classically broken · P2 = hygiene")
    chosen = []
    for i, p in enumerate(S["plan"]):
        c1, c2 = st.columns([0.07, 0.93])
        with c1:
            if st.checkbox(" ", key=f"wf{i}", label_visibility="collapsed"):
                chosen.append(p)
        with c2:
            with st.expander(f"**{p['priority']}** · {p['source']} · {p['action']} · {p['asset_count']} assets · from {', '.join(p['from_algorithms'][:4])}"):
                st.markdown(f"**Standard:** {p['standard']}  \n**How:** {p['how']}")
                st.write(", ".join(p["assets"][:40]) + (" …" if len(p["assets"]) > 40 else ""))
    if chosen:
        sim = copy.deepcopy(findings)
        keys = {(p["source"], p["category"], p["replacement"]) for p in chosen}
        for f in sim:
            cat = f.category if f.category != "authentication" else "signature"
            if f.replacement and (f.source, cat, f.replacement["algorithm"]) in keys:
                f.risk_points, f.risk_tier, f.hndl = 0.0, "safe", False
                if f.algorithm == "PLAINTEXT":
                    f.algorithm = "TLS"
        S2 = summarize(sim)
        st.success(f"What-if: applying {len(chosen)} action(s) moves the Quantum Readiness Score from **{S['quantum_readiness_score']}** to **{S2['quantum_readiness_score']}** (grade {S2['grade']}).")

# ------------------------------------------------------------------ CBOM
with T["CBOM & exports"]:
    bom = cyclonedx.build(findings, S, target="QuantumTrace scan")
    errs = cyclonedx.validate(bom)
    c1, c2, c3 = st.columns(3)
    c1.metric("CBOM components", len(bom["components"]))
    c2.metric("Vulnerabilities", len(bom["vulnerabilities"]))
    c3.metric("CycloneDX 1.6 schema", "valid ✅" if not errs else "not checked ⚠️" if cyclonedx.unvalidated(errs) else "invalid ❌")
    types = pd.Series([c.get("cryptoProperties", {}).get("assetType", c["type"]) for c in bom["components"]]).value_counts().reset_index()
    types.columns = ["assetType", "components"]
    st.dataframe(types, hide_index=True)
    d1, d2, d3 = st.columns(3)
    d1.download_button("⬇ CBOM (CycloneDX 1.6 JSON)", json.dumps(bom, indent=2), "cbom.cdx.json", "application/json")
    d2.download_button("⬇ SARIF (code findings)", json.dumps(sarif.build(findings), indent=2), "results.sarif", "application/json")
    d3.download_button("⬇ Findings + summary (JSON)", json.dumps(dict(summary=S, findings=[f.to_dict() for f in findings]), indent=2, default=str), "quantumtrace-report.json", "application/json")
    with st.expander("Preview CBOM"):
        st.json({k: (v[:5] if isinstance(v, list) else v) for k, v in bom.items()}, expanded=False)

# ------------------------------------------------------------------ accuracy
with T["Accuracy"]:
    if paths == ("samples/official",):
        from quantumtrace.evaluate import run as run_eval
        r = st.cache_data(show_spinner="Scoring against tests/ground_truth.json ...")(lambda: run_eval())()
        off, own = r["code_by_origin"]["official"], r["code_by_origin"]["own_fixtures"]
        st.markdown("**Official challenge data**")
        c1, c2, c3 = st.columns(3)
        c1.metric("Code findings correct", f"{off['correctly_classified']}/{off['expected']}", f"{off['traps_checked']} traps checked", delta_color="off")
        c2.metric("Network sessions correct", f"{r['network']['sessions_correct']}/{r['network']['expected_sessions']}")
        c3.metric("Cloud resources correct", f"{r['cloud']['correct']}/{r['cloud']['expected']}", f"{r['cloud']['traps_checked']} traps checked", delta_color="off")
        st.markdown("**Our own fixtures** (configs, JWT: `samples/extra/code`)")
        c4, c5, _ = st.columns(3)
        c4.metric("Expectations correct", f"{own['correctly_classified']}/{own['expected']}", f"{own['traps_checked']} traps checked", delta_color="off")
        c5.metric("Code precision (all)", f"{r['code']['precision']:.0%}", f"{r['code']['false_positives']} false positives", delta_color="off")
        if r["failures"]:
            st.error("\n".join(r["failures"][:30]))
        else:
            st.success("All expectations in tests/ground_truth.json pass (including false-positive traps).")
    else:
        st.info("Accuracy is measured against the labelled official samples (switch the input in the sidebar).")

# ------------------------------------------------------------------ explain
with T["Explain"]:
    from quantumtrace.classify import classify
    from quantumtrace.schema import Finding
    c1, c2, c3 = st.columns(3)
    alg = c1.selectbox("Algorithm", ["RSA", "ECDSA", "Ed25519", "X25519", "DH", "ML-KEM", "ML-DSA", "X25519MLKEM768", "AES", "3DES", "ChaCha20-Poly1305", "SHA-1", "MD5", "SHA-256", "SHA-384", "HMAC", "PBKDF2"])
    cat = c2.selectbox("Role", ["signature", "key-exchange", "encryption", "hash", "mac", "kdf"])
    prm = c3.text_input("Params (k=v, comma separated)", "key_bits=2048")
    params = {}
    for kv in [x for x in prm.split(",") if "=" in x]:
        kk, vv = kv.split("=", 1)
        params[kk.strip()] = int(vv) if vv.strip().isdigit() else vv.strip()
    f = classify(Finding(source="code", category=cat, algorithm=alg, params=params))
    st.markdown(f"### {f.display_name} {pill(f.risk_tier)}", unsafe_allow_html=True)
    st.write(dict(quantum_threat=f.quantum_threat, classical=f.classical_status, classical_bits=f.classical_bits, nist_quantum_level=f.nist_quantum_level,
                  oid=f.oid, hndl=f.hndl, cwe=f.cwe))
    for w in f.rationale:
        st.markdown(f"- {w}")
    if f.replacement:
        st.success(f"→ {f.replacement['algorithm']} ({f.replacement['standard']}): {f.replacement['how']}")
    for d in f.deadlines:
        st.caption(d)
