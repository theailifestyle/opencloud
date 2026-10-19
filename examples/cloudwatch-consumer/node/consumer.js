// Open CloudWatch SSE consumer for Node (no dependencies).
// Inside an Open Cloud app, CLOUDWATCH_URL and CLOUDWATCH_KEY are files in /run/secrets.
// Prints one JSON line per event. EXIT_ON_TOPIC=alarms makes it exit after the first event of that topic.
const fs = require("fs");
const http = require("http");
const secret = (n) => process.env[n] || (fs.existsSync(`/run/secrets/${n}`) ? fs.readFileSync(`/run/secrets/${n}`, "utf8").trim() : "");
const base = secret("CLOUDWATCH_URL"), key = secret("CLOUDWATCH_KEY");
let lastId = "0";

function connect() {
  const req = http.get(`${base}/v1/stream?topics=alarms,deploys,metrics,audit`,
    { headers: { Authorization: `Bearer ${key}`, "Last-Event-ID": lastId } }, (res) => {
      if (res.statusCode !== 200) { console.error("HTTP", res.statusCode); process.exit(1); }
      let buf = "";
      res.on("data", (chunk) => {
        buf += chunk;
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const block = buf.slice(0, i); buf = buf.slice(i + 2);
          const ev = {};
          for (const line of block.split("\n")) {
            if (line.startsWith("id: ")) ev.id = lastId = line.slice(4);
            else if (line.startsWith("event: ")) ev.topic = line.slice(7);
            else if (line.startsWith("data: ")) ev.data = JSON.parse(line.slice(6));
          }
          if (!ev.data) continue;
          console.log(JSON.stringify(ev));
          if (process.env.EXIT_ON_TOPIC && ev.topic === process.env.EXIT_ON_TOPIC) process.exit(0);
        }
      });
      res.on("end", () => setTimeout(connect, 2000));
    });
  req.on("error", () => setTimeout(connect, 2000));
}
connect();
