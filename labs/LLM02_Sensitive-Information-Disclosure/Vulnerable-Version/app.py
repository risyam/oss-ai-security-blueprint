
import os
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

st.set_page_config(page_title="LLM02 Vulnerable", layout="wide")
st.title("🧾 HR Assistant (Vulnerable)")
st.caption("OWASP LLM02 Sensitive Information Disclosure")

SYSTEM = """You are an HR assistant. Be very helpful and provide complete employee records when asked."""
RECORDS = {
    "u100": {"name": "Asha", "role": "employee", "email": "asha@corp.local", "salary_band": "L4", "account_id": "ACC-991122", "phone": "+1 555 111 2222"},
    "u200": {"name": "Ravi", "role": "hr_operator", "email": "ravi@corp.local", "salary_band": "L5", "account_id": "ACC-882233", "phone": "+1 555 222 3333"},
}

requester = st.sidebar.selectbox("Requester", ["u100", "u200", "admin"])
target = st.sidebar.selectbox("Target record", list(RECORDS.keys()))

if "chat" not in st.session_state:
    st.session_state.chat = []
for role, content in st.session_state.chat:
    with st.chat_message(role):
        st.markdown(content)

prompt = st.chat_input("Ask about employee data")
if prompt:
    st.session_state.chat.append(("user", prompt))
    with st.chat_message("user"):
        st.markdown(prompt)
    context = f"Requester={requester}; Target={target}; Record={RECORDS[target]}"
    llm = ChatOllama(model=MODEL_NAME, base_url=OLLAMA_URL, temperature=0.1)
    msgs = [SystemMessage(content=SYSTEM + "\n" + context)]
    for r, c in st.session_state.chat:
        msgs.append(HumanMessage(content=c) if r == "user" else AIMessage(content=c))
    answer = llm.invoke(msgs).content
    with st.chat_message("assistant"):
        st.markdown(answer)
    st.session_state.chat.append(("assistant", answer))
