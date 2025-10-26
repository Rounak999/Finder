FROM python:3.11-slim
ENV FLASK_APP=app.py \
    FLASK_ENV=production \
    FLASK_RUN_HOST=0.0.0.0 \
    FLASK_RUN_PORT=5000

WORKDIR /app

COPY requirements.txt .

RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libffi-dev build-essential \
    && pip install --no-cache-dir -r requirements.txt \
    && apt-get remove -y gcc build-essential \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Copy app source
COPY . .

# Create a non-root user to run the app
RUN groupadd --system app && useradd --system --gid app --create-home app \
    && chown -R app:app /app

USER app

EXPOSE 5000

# Simple start command — runs your app.py directly
CMD ["python", "./app.py"]
