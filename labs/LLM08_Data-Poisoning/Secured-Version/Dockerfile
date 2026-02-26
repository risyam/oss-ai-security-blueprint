FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends build-essential curl && rm -rf /var/lib/apt/lists/*

# Install Python libraries from a locked set
COPY labs/LLM08_Data-Poisoning/Secured-Version/requirements.lock.txt /tmp/requirements.lock.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r /tmp/requirements.lock.txt

# Copy secure-lib
COPY secure-lib /secure-lib
RUN pip install -e /secure-lib

# Copy app code
COPY labs/LLM08_Data-Poisoning/Secured-Version/app.py .

# Run the app
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]
