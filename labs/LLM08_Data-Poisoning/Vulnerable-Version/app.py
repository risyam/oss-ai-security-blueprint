import os
import streamlit as st
import time

from langchain_community.document_loaders import PyPDFLoader
from langchain_community.vectorstores import Chroma
from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.chat_models import ChatOllama

from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain.chains import RetrievalQA
from langchain.prompts import PromptTemplate

# ==============================
# CONFIGURATION
# ==============================

st.set_page_config(page_title="AI Hiring Assistant (Vulnerable)", layout="centered")
st.title("📄 AI Hiring Assistant (Vulnerable RAG Demo)")

# Get Ollama URL from Docker environment
ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

# Initialize session state for query input if not present
if "query_input" not in st.session_state:
    st.session_state.query_input = ""

# ==============================
# RESET FUNCTIONALITY
# ==============================

def reset_app():
    st.session_state.query_input = ""
    # Clearing the file uploader is tricky in Streamlit without a key
    # We use a key for the uploader and increment it to reset
    if "uploader_key" not in st.session_state:
        st.session_state.uploader_key = 0
    st.session_state.uploader_key += 1
    
    # Clear the vector store from session state
    if "vector_db" in st.session_state:
        del st.session_state.vector_db
        
    st.rerun()

if "uploader_key" not in st.session_state:
    st.session_state.uploader_key = 0

# ==============================
# SIDEBAR - RESET
# ==============================
with st.sidebar:
    st.markdown("### Controls")
    if st.button("🔄 Reset / Start Over"):
        reset_app()

# ==============================
# FILE UPLOAD (Attack Vector)
# ==============================

uploaded_file = st.file_uploader("Upload Candidate Resume (PDF)", type="pdf", key=f"uploader_{st.session_state.uploader_key}")

if uploaded_file:

    # Only process if we haven't already processed this file session
    if "vector_db" not in st.session_state:

        # Save uploaded file (intentionally insecure handling for demo)
        with open("temp_resume.pdf", "wb") as f:
            f.write(uploaded_file.getbuffer())

        # Use spinner for processing indication
        with st.spinner("Processing resume and ingesting into vector database..."):
            # ==============================
            # LOAD + SPLIT DOCUMENT
            # ==============================

            loader = PyPDFLoader("temp_resume.pdf")
            docs = loader.load()

            text_splitter = RecursiveCharacterTextSplitter(
                chunk_size=1000,
                chunk_overlap=100
            )

            docs = text_splitter.split_documents(docs)

            # ==============================
            # EMBEDDINGS (REAL, NOT FAKE)
            # ==============================

            embeddings = OllamaEmbeddings(
                model="llama3",
                base_url=ollama_url
            )

            # ==============================
            # VECTOR DATABASE (Chroma)
            # ==============================

            vector_db = Chroma.from_documents(
                documents=docs,
                embedding=embeddings
            )
            
            # Store in session state to avoid re-processing on every interaction
            st.session_state.vector_db = vector_db
            
            # Simulate a slight delay to make the spinner noticeable if processing is too fast
            time.sleep(1)

    # Use the vector_db from session state
    if "vector_db" in st.session_state:
        vector_db = st.session_state.vector_db

        # Success message appears AFTER spinner finishes
        st.success("Resume ingested successfully! Ask the Hiring Manager Bot below.")

        # ==============================
        # CHAT INTERFACE
        # ==============================

        user_query = st.text_input("Ask about the candidate:")

        if user_query:
            
            with st.spinner("🤖 Thinking..."):
                # Connect to Ollama model server
                llm = ChatOllama(
                    model="llama3",
                    base_url=ollama_url
                )

                # Weak system prompt (intentionally vulnerable)
                prompt_template = """
    You are a Hiring Manager Assistant.
    Answer questions based ONLY on the provided context.

    Context:
    {context}

    Question:
    {question}
    """

                prompt = PromptTemplate(
                    template=prompt_template,
                    input_variables=["context", "question"]
                )

                qa_chain = RetrievalQA.from_chain_type(
                    llm=llm,
                    retriever = vector_db.as_retriever(search_kwargs={"k": 5}),
                    chain_type_kwargs={"prompt": prompt}
                )

                response = qa_chain.run(user_query)

            st.subheader("🤖 Hiring Manager Bot Response")
            st.write(response)


