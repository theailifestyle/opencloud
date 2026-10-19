FROM python:3.12-slim
COPY app.py /app/app.py
RUN useradd -r -u 10101 app
USER app
ENV PORT=8080
CMD ["python", "/app/app.py"]
