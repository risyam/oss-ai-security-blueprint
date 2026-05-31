
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

st.set_page_config(page_title="LLM10 Vulnerable", layout="wide")
st.title("💸 Bulk Summarizer (Vulnerable)")
st.caption("OWASP LLM10 Unbounded Consumption")

text = st.text_area("Input text", value=("A" * 12000))
loops = st.slider("Repeat count", 1, 5, 2)
if st.button("Run summary"):
    llm = ChatOllama(model=MODEL_NAME, base_url=OLLAMA_URL, temperature=0)
    out = ""
    for _ in range(loops):
        out = llm.invoke([SystemMessage(content="Summarize"), HumanMessage(content=text)]).content
    st.success("Completed without budget checks.")
    st.markdown(out)
