FROM docker:27-cli
RUN apk add --no-cache python3 git restic
COPY agent.py /opt/agent/agent.py
CMD ["python3", "/opt/agent/agent.py"]
