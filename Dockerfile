FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure runtime directories exist and edits.json is initialised
RUN mkdir -p logs app/static/edits app/static/img \
    && if [ ! -f app/static/edits/edits.json ]; then echo '{}' > app/static/edits/edits.json; fi

EXPOSE 5000

ENV FLASK_APP=application.py

# Single worker required — CURRENT_USER is a module-level global
CMD ["gunicorn", \
     "--bind", "0.0.0.0:5000", \
     "--workers", "1", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "application:application"]
