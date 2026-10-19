FROM python:3.12-slim
RUN useradd -r -u 10002 gateway
COPY gateway.py /opt/gateway/gateway.py
USER gateway
CMD ["python", "/opt/gateway/gateway.py"]
