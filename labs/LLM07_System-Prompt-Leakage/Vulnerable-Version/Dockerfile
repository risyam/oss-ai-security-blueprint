FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends build-essential curl && rm -rf /var/lib/apt/lists/*

COPY labs/LLM07_System-Prompt-Leakage/Vulnerable-Version/requirements.lock.txt /tmp/requirements.lock.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r /tmp/requirements.lock.txt

COPY labs/LLM07_System-Prompt-Leakage/Vulnerable-Version/app.py .

CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]
