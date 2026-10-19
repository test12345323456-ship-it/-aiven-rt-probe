FROM python:3-alpine
RUN pip install --no-cache-dir "psycopg[binary]"
EXPOSE 8000
COPY probe.py /probe.py
CMD ["python", "/probe.py"]
