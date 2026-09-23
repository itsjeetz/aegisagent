FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DEBIAN_FRONTEND=noninteractive \
    PORT=7860

# Install system dependencies including Tesseract OCR
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    libgl1 \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with UID 1000 for Hugging Face Spaces compatibility
RUN useradd -m -u 1000 user

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy codebase and establish non-root ownership
COPY --chown=user:user . .

# Ensure data and report directories exist and are owned by user (UID 1000)
RUN mkdir -p /app/data/models /app/data/fixtures /app/reports && \
    chown -R user:user /app

# Switch to non-root user
USER user

# Build-time artifact generation: fixtures and ML classifier model
RUN python -m eval.build_dataset && \
    python -m aegis.train

EXPOSE 7860

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "7860"]
