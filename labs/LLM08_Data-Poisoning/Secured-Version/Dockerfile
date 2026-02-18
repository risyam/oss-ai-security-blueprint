FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y build-essential curl

# Install Python libraries
RUN pip install streamlit langchain langchain-community langchain-chroma pypdf ollama requests

# Copy secure-lib
COPY secure-lib /secure-lib
RUN pip install -e /secure-lib

# Copy app code
COPY labs/LLM08_Data-Poisoning/Secured-Version/app.py .

# Run the app
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]
