# Databases

Each app can have one Postgres 17 database. It is a container named `oc-app-<name>-db-1` on a private network. That network is internal: no published port, and the database is not on the network other apps use. Only this app can open a connection.

## Create one

On the app's service page, **Create Postgres database**. The deployer starts Postgres, creates a runtime role, and restarts the app with a new secret file:

```text
/run/secrets/DATABASE_URL
postgresql://app_runtime:<password>@db:5432/app
```

There is no trailing newline. The host name `db` works only inside that app's containers. The password is random and is not shown in the console. The file name appears in the secrets list.

`app_runtime` can connect, use the `public` schema, and `SELECT`, `INSERT`, `UPDATE`, and `DELETE` rows. It is not a superuser and cannot create roles or databases. Tables created later by the owner role are included.

## Schema changes

Run migrations as the owner role `app`, from the server. That role exists only inside the database container:

```bash
sudo docker exec -i oc-app-<app>-db-1 psql -U app -d app < migration.sql
```

Do not put the owner password in the app. The app's password is the `app_runtime` password inside `DATABASE_URL`.

If your app wants separate `DB_HOST` / `DB_USER` variables, save those names as extra secrets (`db`, `5432`, `app_runtime`, `app`) and parse the password out of `DATABASE_URL`. See [APP-GUIDE.md](APP-GUIDE.md).

## Limits

The database container is capped at 512 MB and 0.5 CPU. There is one database per app, named `app`, and no read replica, no extension installer in the console, and no public endpoint.

## Backups

**Back up now** runs `pg_dumpall` inside each app database and stores the dump under `$OC_ROOT/backups/postgres/` before the restic snapshot. Raw data directories are not the backup. Restore steps are in [RESTORE.md](RESTORE.md).

## Remove

Deleting the app removes its database. On the service page, **Delete app** (see [DEPLOY.md](DEPLOY.md)) stops the database container, deletes `$OC_ROOT/pgdata/<app>/`, and deletes the credential files `$OC_ROOT/secrets/db/<app>` and `$OC_ROOT/secrets/db/<app>-runtime`. Leave **Take a final backup first** on if you want a `pg_dump` before that happens. The dump uses `-U app` only after the deployer has checked the container name, compose project, `opencloud.backup=postgres` label, image, and `POSTGRES_USER=app`. There is no separate button that drops only the database.
