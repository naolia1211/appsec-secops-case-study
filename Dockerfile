FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/build/deps -r requirements.txt

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/service/deps
WORKDIR /service
# pip/setuptools ship in the base image but are never invoked at runtime;
# dropping them removes their CVEs from the image, not just the version pin.
RUN useradd --uid 10001 --create-home appuser \
 && rm -rf /usr/local/lib/python3.12/site-packages/pip* /usr/local/lib/python3.12/site-packages/setuptools* /usr/local/bin/pip*
COPY --from=builder /build/deps ./deps
COPY app ./app
COPY run.py .
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"
CMD ["python", "run.py"]
