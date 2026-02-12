FROM python:3.9-slim

WORKDIR /app

# Install system dependencies (needed for some PDF loaders)
RUN apt-get update && apt-get install -y build-essential curl

# Install Python libraries
RUN pip install streamlit langchain langchain-community langchain-chroma pypdf ollama

# Copy your app code
COPY app.py .

# Run the app
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]