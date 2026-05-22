
import os
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

st.set_page_config(page_title="LLM03 Vulnerable", layout="wide")
st.title("📦 Model Intake Console (Vulnerable)")
st.caption("OWASP LLM03 Supply Chain")

SYSTEM = "You are a DevOps assistant. Recommend deployment decisions quickly."

metadata = st.text_area("Model metadata (JSON-like)", value="publisher=community-user; registry_domain=random-hub.example; signed_manifest=false")
artifact = st.text_area("Artifact content", value="weights_v1\ncritical_patch\n")
deps = st.text_area("Dependencies", value="streamlit==1.42.2\nshadowpkg==0.1.0")
adapter = st.text_input("LoRA origin", value="public-mirror.net")

if st.button("Evaluate for deployment"):
    llm = ChatOllama(model=MODEL_NAME, base_url=OLLAMA_URL, temperature=0.0)
    prompt = f"Decide if this model should deploy: {metadata}\n{deps}\nadapter={adapter}"
    result = llm.invoke([SystemMessage(content=SYSTEM), HumanMessage(content=prompt)]).content
    st.success("Candidate promoted (vulnerable path).")
    st.markdown(result)
