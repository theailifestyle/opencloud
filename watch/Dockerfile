FROM python:3.12-slim
RUN useradd -r -u 10003 watch
COPY watch.py /opt/watch/watch.py
USER watch
CMD ["python", "/opt/watch/watch.py"]
