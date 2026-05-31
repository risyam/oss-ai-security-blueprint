
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

st.set_page_config(page_title="LLM10 Secured", layout="wide")
st.title("💸 Bulk Summarizer (Secured)")
st.caption("OWASP LLM10 Unbounded Consumption")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "secure-lib"))
from secure_lib.monitoring.rate_limiter import RateLimiter
from secure_lib.monitoring.token_limit_enforcer import TokenLimitEnforcer
from secure_lib.monitoring.anomaly_traffic_detector import AnomalyTrafficDetector
from secure_lib.monitoring.concurrency_limiter import ConcurrencyLimiter
from secure_lib.monitoring.cost_budget_guard import CostBudgetGuard
from secure_lib.monitoring.extraction_pattern_detector import ExtractionPatternDetector

if "rate" not in st.session_state:
    st.session_state.rate = RateLimiter(max_requests=5, window_seconds=60)
if "token" not in st.session_state:
    st.session_state.token = TokenLimitEnforcer(max_input_tokens=2500, max_output_tokens=1000, session_budget=12000)
if "anomaly" not in st.session_state:
    st.session_state.anomaly = AnomalyTrafficDetector(burst_threshold=4, window_seconds=5)
if "conc" not in st.session_state:
    st.session_state.conc = ConcurrencyLimiter(max_in_flight=2)
if "budget" not in st.session_state:
    st.session_state.budget = CostBudgetGuard(budget_usd=0.35)
if "events" not in st.session_state:
    st.session_state.events = []
extract = ExtractionPatternDetector()

with st.sidebar:
    st.subheader("Security Events")
    for e in st.session_state.events[-12:]:
        st.json(e)

text = st.text_area("Input text", value=("A" * 12000))
client = st.text_input("Client ID", value="demo-user")

if st.button("Run summary"):
    anomaly = st.session_state.anomaly.record_and_check()
    st.session_state.events.append({"control": "AnomalyTrafficDetector", "suspicious": anomaly.suspicious, "reason": anomaly.reason})
    if anomaly.suspicious:
        st.error("Blocked: burst traffic pattern detected.")
        st.stop()

    rate = st.session_state.rate.check_and_record(client)
    st.session_state.events.append(rate.to_log_entry())
    if not rate.allowed:
        st.error("Blocked: rate limit exceeded.")
        st.stop()

    ext = extract.scan(text)
    st.session_state.events.append({"control": "ExtractionPatternDetector", "suspicious": ext.suspicious, "reason": ext.reason})
    if ext.suspicious:
        st.error("Blocked: extraction probing pattern detected.")
        st.stop()

    slot = st.session_state.conc.acquire()
    st.session_state.events.append({"control": "ConcurrencyLimiter", "allowed": slot.allowed, "reason": slot.reason, "in_flight": slot.in_flight})
    if not slot.allowed:
        st.error("Blocked: too many in-flight requests.")
        st.stop()

    try:
        inp = st.session_state.token.check_input(text)
        st.session_state.events.append(inp.to_log_entry())
        if not inp.allowed:
            st.error(f"Blocked: {inp.reason}")
            st.stop()

        est_cost = max(inp.estimated_tokens / 10000 * 0.02, 0.01)
        budget = st.session_state.budget.check(est_cost)
        st.session_state.events.append({"control": "CostBudgetGuard", "allowed": budget.allowed, "reason": budget.reason, "used": budget.used, "budget": budget.budget})
        if not budget.allowed:
            st.error("Blocked: cost budget exceeded.")
            st.stop()

        llm = ChatOllama(model=MODEL_NAME, base_url=OLLAMA_URL, temperature=0)
        out = llm.invoke([SystemMessage(content="Summarize safely in 3 bullets."), HumanMessage(content=text)]).content

        out_check = st.session_state.token.check_output(out)
        st.session_state.events.append(out_check.to_log_entry())
        if not out_check.allowed:
            st.error(f"Blocked: {out_check.reason}")
            st.stop()

        st.session_state.token.record_usage(inp.estimated_tokens, out_check.estimated_tokens)
        st.session_state.budget.record(est_cost)
        st.markdown(out)
    finally:
        st.session_state.conc.release()
