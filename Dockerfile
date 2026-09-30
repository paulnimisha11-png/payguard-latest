FROM python:3.11-slim
WORKDIR /srv
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr espeak-ng libgl1 libglib2.0-0 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY static ./static
RUN mkdir -p ./downloads
ENV APKXRAY_DB=/data/apkxray.db PORT=8000 OCR_ENGINE=tesseract APKXRAY_OCR_ENGINE=tesseract APKXRAY_WORKERS=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
VOLUME /data

EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --proxy-headers --forwarded-allow-ips='*'"]
