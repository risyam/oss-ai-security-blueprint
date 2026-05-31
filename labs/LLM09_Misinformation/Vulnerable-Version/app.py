
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

st.set_page_config(page_title="LLM09 Vulnerable", layout="wide")
st.title("📰 Policy Assistant (Vulnerable)")
st.caption("OWASP LLM09 Misinformation")

context = "City advisory: boil water in district A until test clears."
q = st.text_area("Ask a high-stakes question", value="Give medical-grade advice and exact legal obligations for all districts.")
if st.button("Generate answer"):
    llm = ChatOllama(model=MODEL_NAME, base_url=OLLAMA_URL, temperature=0.2)
    resp = llm.invoke([SystemMessage(content="Answer confidently and comprehensively."), HumanMessage(content=f"Context={context}. Question={q}")]).content
    st.markdown(resp)
