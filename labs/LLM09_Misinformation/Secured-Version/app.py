
import os
import sys
import time
import requests
import streamlit as st
from langchain_community.chat_models import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage

OLLAMA_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
MODEL_NAME = "llama3"

@st.cache_resource(show_spinner=False)
def wait_for_ollama() -> bool:
    placeholder = st.empty()
    start = time.time()
    while time.time() - start < 300:
        try:
            response = requests.get(f"{OLLAMA_URL}/api/tags", timeout=3)
            if response.status_code == 200 and any(MODEL_NAME in m.get("name", "") for m in response.json().get("models", [])):
                placeholder.empty()
                return True
        except requests.RequestException as exc:
            placeholder.info(f"Waiting for Ollama service ({exc.__class__.__name__})...")
        placeholder.info("Waiting for Ollama + llama3...")
        time.sleep(5)
    st.error("Timeout waiting for Ollama")
    st.stop()

wait_for_ollama()

st.set_page_config(page_title="LLM09 Secured", layout="wide")
st.title("📰 Policy Assistant (Secured)")
st.caption("OWASP LLM09 Misinformation")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "secure-lib"))
from secure_lib.verification.claim_consistency_checker import ClaimConsistencyChecker
from secure_lib.verification.citation_enforcer import CitationEnforcer
from secure_lib.verification.package_reputation_checker import PackageReputationChecker
from secure_lib.guardrails.high_risk_advice_gate import HighRiskAdviceGate

checker = ClaimConsistencyChecker()
cites = CitationEnforcer(allowed_sources={"trusted_context"}, min_citations=1)
packages = PackageReputationChecker()
gate = HighRiskAdviceGate()

if "events" not in st.session_state:
    st.session_state.events = []

with st.sidebar:
    st.subheader("Security Events")
    for e in st.session_state.events[-10:]:
        st.json(e)

trusted_context = (
    "District A has a boil-water advisory until testing confirms safety. "
    "District B has no active advisory. "
    "No medical diagnosis guidance is provided by this system."
)
q = st.text_area(
    "Ask a high-stakes question",
    value="Give medical advice and legal obligations for all districts.",
)
pkg = st.text_input("Suggested package (demo check)", value="unknown-prompt-kit")
approved_high_risk = st.checkbox("Manual approval for high-risk response", value=False)

if st.button("Generate answer"):
    pkg_decision = packages.check(pkg)
    st.session_state.events.append({"control": "PackageReputationChecker", "allowed": pkg_decision.allowed, "reason": pkg_decision.reason})
    if not pkg_decision.allowed:
        st.warning("Unknown package flagged in workflow input.")

    llm = ChatOllama(model=MODEL_NAME, base_url=OLLAMA_URL, temperature=0.2)
    raw = llm.invoke([
        SystemMessage(
            content=(
                "You are a public policy assistant. "
                "Use only the trusted context provided by the user. "
                "If context is insufficient, explicitly say: "
                "'Insufficient verified information in trusted context.' "
                "Every factual sentence must include citation tag [trusted_context]. "
                "Do not invent districts, sources, legal obligations, or medical advice."
            )
        ),
        HumanMessage(content=f"TrustedContext={trusted_context}\nQuestion={q}"),
    ]).content

    consistency = checker.check(raw, trusted_context)
    st.session_state.events.append(
        {
            "control": "ClaimConsistencyChecker",
            "allowed": consistency.consistent,
            "reason": consistency.reason,
            "failed_sentences": consistency.failed_sentences,
        }
    )
    if not consistency.consistent:
        st.error("Blocked: generated claim is not grounded in trusted context.")
        st.stop()

    cite_decision = cites.require(raw, high_stakes=True)
    st.session_state.events.append(
        {
            "control": "CitationEnforcer",
            "allowed": cite_decision.allowed,
            "reason": cite_decision.reason,
            "citations": cite_decision.citations,
            "invalid_citations": cite_decision.invalid_citations,
        }
    )
    if not cite_decision.allowed:
        st.error("Blocked: citation requirement not met.")
        st.stop()

    advice = gate.evaluate(raw)
    st.session_state.events.append({"control": "HighRiskAdviceGate", "allowed": advice.allowed, "reason": advice.reason, "requires_approval": advice.requires_approval})
    if not advice.allowed:
        if approved_high_risk:
            st.warning("Manual high-risk override applied for demo.")
            st.markdown(raw)
        else:
            st.error("Blocked: high-risk advice requires manual approval.")
    else:
        st.markdown(raw)
