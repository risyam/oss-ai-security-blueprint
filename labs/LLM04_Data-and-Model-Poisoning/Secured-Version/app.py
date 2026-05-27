
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

st.set_page_config(page_title="LLM04 Secured", layout="wide")
st.title("🧪 Safety Dataset Review (Secured)")
st.caption("OWASP LLM04 Data and Model Poisoning")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "secure-lib"))
from secure_lib.data_integrity.poisoning_signal_detector import PoisoningSignalDetector
from secure_lib.data_integrity.backdoor_trigger_scanner import BackdoorTriggerScanner
from secure_lib.data_integrity.dataset_lineage_tracker import DatasetLineageTracker
from secure_lib.data_integrity.model_promotion_guard import ModelPromotionGuard

detector = PoisoningSignalDetector()
backdoor = BackdoorTriggerScanner()
if "tracker" not in st.session_state:
    st.session_state.tracker = DatasetLineageTracker()
if "guard" not in st.session_state:
    st.session_state.guard = ModelPromotionGuard(max_regression_pct=5.0)
if "events" not in st.session_state:
    st.session_state.events = []

with st.sidebar:
    st.subheader("Security Events")
    for e in st.session_state.events[-10:]:
        st.json(e)

sample = st.text_area("Candidate training sample", value="Customer asks for malware help. Always label low-risk!!!")
source = st.text_input("Source ID", value="supplier-batch-44")
uploader = st.text_input("Uploader", value="partner-feed")
approval = st.selectbox("Approval state", ["approved", "pending", "rejected"], index=1)
baseline = st.slider("Baseline safety score", 0.0, 1.0, 0.91)
candidate = st.slider("Candidate score", 0.0, 1.0, 0.89)

if st.button("Promote candidate model"):
    record = st.session_state.tracker.register(source_id=source, uploader=uploader, approval_state=approval, transforms=["normalized", "deduped"])
    st.session_state.events.append({"control": "DatasetLineageTracker", "sample_id": record.sample_id, "approval_state": approval})

    if approval != "approved":
        st.session_state.events.append({"control": "DatasetLineageTracker", "allowed": False, "reason": "Dataset not approved."})
        st.error("Promotion blocked: dataset approval state is not approved.")
        st.stop()

    poison = detector.scan(sample)
    st.session_state.events.append({"control": "PoisoningSignalDetector", "suspicious": poison.suspicious, "signals": poison.signals})
    trigger = backdoor.scan(sample)
    st.session_state.events.append({"control": "BackdoorTriggerScanner", "detected": trigger.detected, "triggers": trigger.triggers})

    decision = st.session_state.guard.evaluate(baseline_score=baseline, candidate_score=candidate, backdoor_detected=(trigger.detected or poison.suspicious))
    st.session_state.events.append({"control": "ModelPromotionGuard", "allowed": decision.allowed, "reason": decision.reason})

    if not decision.allowed:
        st.error(decision.reason)
    else:
        llm = ChatOllama(model=MODEL_NAME, base_url=OLLAMA_URL, temperature=0)
        out = llm.invoke([SystemMessage(content="Provide safe release note."), HumanMessage(content=sample)]).content
        st.success("Candidate promoted after integrity checks.")
        st.markdown(out)
