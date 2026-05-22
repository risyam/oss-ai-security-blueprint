
import os
import sys
import time
import requests
import streamlit as st
from langchain_community.chat_models import ChatOllama
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

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

st.set_page_config(page_title="LLM02 Secured", layout="wide")
st.title("🧾 HR Assistant (Secured)")
st.caption("OWASP LLM02 Sensitive Information Disclosure")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "secure-lib"))
from secure_lib.privacy.tenant_scope_enforcer import TenantScopeEnforcer
from secure_lib.privacy.field_access_policy import FieldAccessPolicy
from secure_lib.privacy.data_minimizer import DataMinimizer
from secure_lib.privacy.pii_redactor import PIIRedactor

SYSTEM = """You are an HR assistant. Use only provided sanitized context and avoid exposing hidden identifiers."""
RECORDS = {
    "u100": {"name": "Asha", "role": "employee", "email": "asha@corp.local", "salary_band": "L4", "account_id": "ACC-991122", "phone": "+1 555 111 2222"},
    "u200": {"name": "Ravi", "role": "hr_operator", "email": "ravi@corp.local", "salary_band": "L5", "account_id": "ACC-882233", "phone": "+1 555 222 3333"},
}
CLASS = {"name": "public", "role": "internal", "email": "internal", "salary_band": "restricted", "account_id": "restricted", "phone": "restricted"}
REQUESTER_ROLES = {"u100": "employee", "u200": "hr_operator", "admin": "admin"}

tenant = TenantScopeEnforcer()
policy = FieldAccessPolicy(CLASS)
minimizer = DataMinimizer()
redactor = PIIRedactor()

if "events" not in st.session_state:
    st.session_state.events = []
if "chat" not in st.session_state:
    st.session_state.chat = []

def log_event(item: dict):
    st.session_state.events.append(item)

with st.sidebar:
    st.subheader("Security Events")
    for e in st.session_state.events[-8:]:
        st.json(e)

requester = st.sidebar.selectbox("Requester", ["u100", "u200", "admin"])
requester_role = REQUESTER_ROLES[requester]
st.sidebar.caption(f"Resolved role: `{requester_role}` (identity-bound)")
target = st.sidebar.selectbox("Target record", list(RECORDS.keys()))

for role, content in st.session_state.chat:
    with st.chat_message(role):
        st.markdown(content)

prompt = st.chat_input("Ask about employee data")
if prompt:
    st.session_state.chat.append(("user", prompt))
    with st.chat_message("user"):
        st.markdown(prompt)

    scope = tenant.is_allowed(requester, target, requester_role)
    log_event(scope.to_log_entry())
    if not scope.allowed:
        answer = "Blocked: cross-user access is denied for this role."
    else:
        filtered = policy.filter_record(RECORDS[target], requester_role)
        minimal = minimizer.summarize(filtered, list(filtered.keys()))
        safe_context = redactor.redact(minimal)
        pii_scan = redactor.scan(minimal)
        if pii_scan.findings:
            log_event({"threat_type": "pii_redaction", "detected_by": "pii_redactor", "action_taken": "masked", "findings": pii_scan.findings})
        llm = ChatOllama(model=MODEL_NAME, base_url=OLLAMA_URL, temperature=0.1)
        msgs = [SystemMessage(content=SYSTEM + "\nAuthorized context: " + safe_context)]
        for r, c in st.session_state.chat:
            msgs.append(HumanMessage(content=c) if r == "user" else AIMessage(content=c))
        answer = llm.invoke(msgs).content
        out_scan = redactor.scan(answer)
        if out_scan.findings:
            log_event({"threat_type": "output_pii", "detected_by": "pii_redactor", "action_taken": "redacted", "findings": out_scan.findings})
            answer = redactor.redact(answer)

    with st.chat_message("assistant"):
        st.markdown(answer)
    st.session_state.chat.append(("assistant", answer))
