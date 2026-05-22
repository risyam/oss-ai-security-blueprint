
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

st.set_page_config(page_title="LLM03 Secured", layout="wide")
st.title("📦 Model Intake Console (Secured)")
st.caption("OWASP LLM03 Supply Chain")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "secure-lib"))
from secure_lib.supply_chain.model_provenance_registry import ModelProvenanceRegistry
from secure_lib.supply_chain.artifact_integrity_verifier import ArtifactIntegrityVerifier
from secure_lib.supply_chain.dependency_policy_enforcer import DependencyPolicyEnforcer
from secure_lib.supply_chain.lora_adapter_policy import LoraAdapterPolicy

prov = ModelProvenanceRegistry()
integrity = ArtifactIntegrityVerifier()
dep_policy = DependencyPolicyEnforcer(approved={"streamlit": "1.42.2", "requests": "2.32.3"}, blocked_packages={"shadowpkg", "unknown-loader"})
adapter_policy = LoraAdapterPolicy()

if "events" not in st.session_state:
    st.session_state.events = []

with st.sidebar:
    st.subheader("Security Events")
    for e in st.session_state.events[-10:]:
        st.json(e)

trusted = st.toggle("Use trusted metadata", value=False)
if trusted:
    metadata = {"publisher": "trusted-ai-labs", "registry_domain": "registry.internal.ai", "signed_manifest": True}
    artifact_content = b"trusted-weights-v1"
    deps = {"streamlit": "1.42.2", "requests": "2.32.3"}
    adapter_meta = {"origin": "registry.internal.ai"}
else:
    metadata = {"publisher": "community-user", "registry_domain": "random-hub.example", "signed_manifest": False}
    artifact_content = b"trusted-weights-v1 tampered"
    deps = {"streamlit": "1.42.2", "shadowpkg": "0.1.0"}
    adapter_meta = {"origin": "public-mirror.net"}

expected_sha = "6500f753b6e7ce70d68a0f3727d517fef2905b492bd7d0ad4f70bdb08f22f823"

if st.button("Evaluate for deployment"):
    ok = True
    p = prov.validate(metadata)
    st.session_state.events.append({"control": "ModelProvenanceRegistry", "allowed": p.allowed, "reason": p.reason})
    ok = ok and p.allowed

    i = integrity.verify(artifact_content, expected_sha)
    st.session_state.events.append({"control": "ArtifactIntegrityVerifier", "allowed": i.valid, "reason": i.reason})
    ok = ok and i.valid

    d = dep_policy.validate(deps)
    st.session_state.events.append({"control": "DependencyPolicyEnforcer", "allowed": d.allowed, "reason": d.reason, "violations": d.violations})
    ok = ok and d.allowed

    a = adapter_policy.validate(adapter_meta, "llama3")
    st.session_state.events.append({"control": "LoraAdapterPolicy", "allowed": a.allowed, "reason": a.reason})
    ok = ok and a.allowed

    if not ok:
        st.error("Deployment blocked by deterministic supply-chain controls.")
    else:
        llm = ChatOllama(model=MODEL_NAME, base_url=OLLAMA_URL, temperature=0.0)
        out = llm.invoke([SystemMessage(content="Summarize why this candidate is safe."), HumanMessage(content=str(metadata))]).content
        st.success("Candidate promoted after all controls passed.")
        st.markdown(out)
