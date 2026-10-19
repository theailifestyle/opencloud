// Open Cloud example: Express using Postgres, a bucket, the Model Gateway and /data.
const fs = require("fs");
const express = require("express");
const { Pool } = require("pg");
const { S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3");

const secret = (n, d) => { try { return fs.readFileSync(`/run/secrets/${n}`, "utf8"); } catch { return d; } };
const app = express();

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/demo", async (req, res) => {
  const out = {};
  try {
    if (secret("DATABASE_URL")) {
      const db = new Pool({ connectionString: secret("DATABASE_URL") });
      out.db = (await db.query("select 1 as one")).rows[0].one === 1;
      await db.end();
    }
    if (secret("S3_ACCESS_KEY_ID") && secret("S3_BUCKET")) {
      const s3 = new S3Client({ endpoint: secret("S3_ENDPOINT"), region: "us-east-1", forcePathStyle: true,
        credentials: { accessKeyId: secret("S3_ACCESS_KEY_ID"), secretAccessKey: secret("S3_SECRET_ACCESS_KEY") } });
      await s3.send(new PutObjectCommand({ Bucket: secret("S3_BUCKET"), Key: "demo.txt", Body: "hello from express" }));
      const got = await s3.send(new GetObjectCommand({ Bucket: secret("S3_BUCKET"), Key: "demo.txt" }));
      out.bucket = (await got.Body.transformToString()) === "hello from express";
    }
    if (secret("LLM_GATEWAY_KEY")) {
      const r = await fetch(secret("LLM_GATEWAY_URL") + "/chat/completions", { method: "POST",
        headers: { Authorization: "Bearer " + secret("LLM_GATEWAY_KEY"), "Content-Type": "application/json" },
        body: JSON.stringify({ model: secret("LLM_MODEL", "chat-fast"), messages: [{ role: "user", content: "hi" }] }) });
      out.gateway = (await r.json()).choices[0].message.content;
    }
    const p = "/data/visits";
    fs.writeFileSync(p, String((fs.existsSync(p) ? Number(fs.readFileSync(p, "utf8")) : 0) + 1));
    out.data_visits = Number(fs.readFileSync(p, "utf8"));
    res.json(out);
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
});

app.listen(Number(process.env.PORT || 3000), "0.0.0.0");
