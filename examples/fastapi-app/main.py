"""Open Cloud example: FastAPI using Postgres, a bucket, the Model Gateway and /data."""
import json, urllib.request
from pathlib import Path

import boto3, psycopg
from botocore.config import Config
from fastapi import FastAPI

app = FastAPI(title="Open Cloud FastAPI example")


def secret(name, default=None):
    p = Path("/run/secrets") / name
    return p.read_text() if p.exists() else default


@app.get("/health", summary="Health check")
def health():
    return {"ok": True}


@app.get("/items", summary="Count items in Postgres")
def items():
    with psycopg.connect(secret("DATABASE_URL")) as db:
        db.execute("create table if not exists items (id serial primary key, name text)")
        return {"count": db.execute("select count(*) from items").fetchone()[0]}


@app.post("/items", summary="Add an item")
def add_item(name: str = "example"):
    with psycopg.connect(secret("DATABASE_URL")) as db:
        db.execute("create table if not exists items (id serial primary key, name text)")
        db.execute("insert into items (name) values (%s)", (name,))
    return {"ok": True}


@app.get("/demo", summary="Exercise every connected service")
def demo():
    out = {}
    if secret("DATABASE_URL"):
        with psycopg.connect(secret("DATABASE_URL")) as db:
            out["db"] = db.execute("select 1").fetchone()[0] == 1
    if secret("S3_ACCESS_KEY_ID") and secret("S3_BUCKET"):
        s3 = boto3.client("s3", endpoint_url=secret("S3_ENDPOINT"), region_name="us-east-1",
                          aws_access_key_id=secret("S3_ACCESS_KEY_ID"), aws_secret_access_key=secret("S3_SECRET_ACCESS_KEY"),
                          config=Config(s3={"addressing_style": "path"}))
        s3.put_object(Bucket=secret("S3_BUCKET"), Key="demo.txt", Body=b"hello from fastapi")
        out["bucket"] = s3.get_object(Bucket=secret("S3_BUCKET"), Key="demo.txt")["Body"].read() == b"hello from fastapi"
    if secret("LLM_GATEWAY_KEY"):
        req = urllib.request.Request(secret("LLM_GATEWAY_URL") + "/chat/completions", method="POST",
                                     data=json.dumps({"model": secret("LLM_MODEL", "chat-fast"), "messages": [{"role": "user", "content": "hi"}]}).encode(),
                                     headers={"Authorization": "Bearer " + secret("LLM_GATEWAY_KEY"), "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            out["gateway"] = json.loads(r.read())["choices"][0]["message"]["content"]
    p = Path("/data/visits")
    p.write_text(str(int(p.read_text() or 0) + 1) if p.exists() else "1")
    out["data_visits"] = int(p.read_text())
    return out
