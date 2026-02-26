FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (needed for some PDF loaders)
RUN apt-get update && apt-get install -y --no-install-recommends build-essential curl && rm -rf /var/lib/apt/lists/*

# Install Python libraries from a locked set
COPY requirements.lock.txt /tmp/requirements.lock.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r /tmp/requirements.lock.txt

# Copy your app code
COPY app.py .

# Run the app
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0"]
