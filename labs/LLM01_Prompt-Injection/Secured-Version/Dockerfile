FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

COPY labs/LLM01_Prompt-Injection/Secured-Version/requirements.lock.txt /tmp/requirements.lock.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r /tmp/requirements.lock.txt

# Copy and install reusable security controls.
COPY secure-lib /secure-lib
RUN pip install -e /secure-lib

COPY labs/LLM01_Prompt-Injection/Secured-Version/app.py .

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]
