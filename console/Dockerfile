FROM python:3.12-slim
RUN useradd -r -u 10001 console
# QR codes for two-step login setup (pure Python, pinned by hash).
RUN echo 'segno==1.6.6 --hash=sha256:28c7d081ed0cf935e0411293a465efd4d500704072cdb039778a2ab8736190c7' > /tmp/req.txt \
 && pip install --no-cache-dir --require-hashes -r /tmp/req.txt && rm /tmp/req.txt
COPY console.py /opt/console/console.py
USER console
CMD ["python", "/opt/console/console.py"]
