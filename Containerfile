FROM python:3-alpine
EXPOSE 8000
COPY probe.py /probe.py
CMD ["python", "/probe.py"]
