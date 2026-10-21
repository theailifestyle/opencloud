# Storage and static sites

Open Cloud has two ways to keep files: a bucket the app talks to (Open S3), and a directory the edge serves as a website (static sites). Both use the same SeaweedFS process (`oc-storage`). Anonymous access is off.

## Buckets

On the app's service page, create a bucket. The name is yours (`my-app-files`). The deployer creates an access key that can only touch that app's buckets and restarts the app with these files in `/run/secrets/`:

| File | Value |
|---|---|
| `S3_ENDPOINT` | `http://storage:8333` (from inside an app) |
| `S3_PUBLIC_ENDPOINT` | `https://<OC_S3_HOST>` (URLs a browser will open) |
| `S3_ACCESS_KEY_ID` | this app's key |
| `S3_SECRET_ACCESS_KEY` | this app's secret |

The bucket name is not injected. Save it yourself as a secret, for example `S3_BUCKET`, if the app should not hardcode it.

Use path-style addressing and any region string (`us-east-1` is fine). Virtual-hosted bucket URLs will not match this endpoint.

```python
import boto3
from botocore.config import Config
s3 = boto3.client(
    "s3",
    endpoint_url=open("/run/secrets/S3_ENDPOINT").read(),
    region_name="us-east-1",
    aws_access_key_id=open("/run/secrets/S3_ACCESS_KEY_ID").read(),
    aws_secret_access_key=open("/run/secrets/S3_SECRET_ACCESS_KEY").read(),
    config=Config(s3={"addressing_style": "path"}),
)
```

Presigned URLs must be signed against `S3_PUBLIC_ENDPOINT`, because the browser cannot resolve `storage:8333`. That public name is `OC_S3_HOST` (example: `s3.apps.example.com`), which the apps wildcard already covers. Set `OC_S3_PUBLIC=0` in `.env` and re-run `install.sh` if you do not want that hostname at all. Apps still use `S3_ENDPOINT` inside the server.

Another app's key cannot read this app's bucket. There is one storage admin identity, generated at install, in `$OC_ROOT/secrets/storage/s3.json`. It is not given to apps.

SeaweedFS's master, filer, and volume ports bind to loopback inside the container. Only the S3 port is on the app network.

`/data` on an app container is a different thing: a normal directory on disk, owned by the user in the image, included in backups. It is not a bucket. See [APP-GUIDE.md](APP-GUIDE.md).

Deleting the app removes its buckets and its S3 key, then restarts object storage so the key stops working. A bucket is removed only when no other identity has `Read`, `Write`, `List`, `Tagging`, or `Admin` on that bucket. The platform admin key is bare `Admin` and does not block this. The shared `sites` bucket is not one of those buckets. Managed `/data` is removed with the app; a host folder mounted from `OC_ALLOWED_DATA_ROOTS` is not. See [DEPLOY.md](DEPLOY.md).

## Static sites

Static sites are HTML, CSS, and JavaScript with no server process. You upload a single `.html` file or a `.zip` in the console (**Static sites**). The bytes are stored in a private bucket named `sites` and unpacked into `$OC_ROOT/sites/<name>/`. The edge serves the `current` release with `file_server`. The edge never calls the storage API, so a website cannot list the bucket.

Uploads are limited to 10 MB, 50 MB unpacked, and 2000 files. Zip entries with `..`, absolute paths, or symlinks are rejected. `index.html` is required.

Attach domains on the site page. While DNS does not point here yet, tick **DNS not ready (preview certificate)** so Caddy does not hammer Let's Encrypt. Untick it, or use **Switch to real certificate** on the DNS page, once the names resolve to this server.

The full behavior (caching, headers, www redirect, delete) is [STATIC-SITES.md](STATIC-SITES.md). Pointing a domain is [DNS.md](DNS.md).

## Backups

Object storage is copied while SeaweedFS is running, so a backup is best effort for objects written during the copy. Static site files on disk are part of that copy. Restore steps are in [RESTORE.md](RESTORE.md).
