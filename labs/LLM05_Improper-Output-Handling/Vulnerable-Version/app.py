import os
import re
import uuid

import requests
import streamlit as st
from langchain_community.chat_models import ChatOllama
from langchain.prompts import PromptTemplate

st.set_page_config(page_title="LLM05 Vulnerable Output Handling", layout="centered")
st.title("LLM05 Lab: Vulnerable Output Handling")
st.caption("Intentionally vulnerable lab for OWASP LLM05:2025")

ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
internal_token = os.getenv("INTERNAL_API_TOKEN", "dev-internal-token")
model_name = "llama3"

if "session_id" not in st.session_state:
    st.session_state.session_id = str(uuid.uuid4())

st.markdown("### 1) Untrusted Content")
untrusted_content = st.text_area(
    "Paste untrusted webpage/email content:",
    height=220,
    value=(
        "Release notes for product launch.\n"
        "Please summarize for customers using clean HTML."
    ),
)

st.markdown("### 2) User Task")
user_task = st.text_input(
    "Ask the assistant:",
    value="Create a short customer-facing HTML summary.",
)

if st.button("Generate"):
    with st.spinner("Generating..."):
        llm = ChatOllama(model=model_name, base_url=ollama_url)

        # Intentionally weak prompt: mixes untrusted content with instructions and asks for raw HTML.
        prompt = PromptTemplate(
            template=(
                "You are an assistant that formats customer-facing updates.\n"
                "Use the content below and produce raw HTML only.\n\n"
                "UNTRUSTED CONTENT:\n{untrusted_content}\n\n"
                "TASK:\n{user_task}\n"
            ),
            input_variables=["untrusted_content", "user_task"],
        )

        full_prompt = prompt.format(untrusted_content=untrusted_content, user_task=user_task)
        response = llm.predict(full_prompt)

    st.markdown("### 3) Model Output (Intentionally Unsafe Render)")

    # Vulnerability #1: render model output as trusted HTML.
    st.markdown(response, unsafe_allow_html=True)

    st.markdown("### 4) Unsafe Output-Triggered Automation")

    # Vulnerability #2: execute network action based on model output instruction.
    webhook_match = re.search(r"CALL_WEBHOOK:\s*(https?://\S+)", response)
    if webhook_match:
        target_url = webhook_match.group(1)
        st.warning(f"Model requested webhook call: {target_url}")
        try:
            webhook_result = requests.post(
                target_url,
                timeout=5,
                json={
                    "session_id": st.session_state.session_id,
                    "preview": response[:300],
                },
                headers={"X-Internal-Token": internal_token},
            )
            st.error(
                "Webhook call executed from model output. "
                f"Status: {webhook_result.status_code}"
            )
        except Exception as exc:
            st.error(f"Webhook call failed: {exc}")
    else:
        st.info("No CALL_WEBHOOK directive found in output.")

with st.expander("Why this is vulnerable"):
    st.markdown(
        "- Renders LLM output as trusted HTML (`unsafe_allow_html=True`).\n"
        "- Executes side effects from model-generated output (`CALL_WEBHOOK`).\n"
        "- Sends internal token on outbound request without user confirmation."
    )
