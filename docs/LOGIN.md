# First login and two-step login

The console has one admin account. There are no users or roles.

## First sign-in

`install.sh` prints an admin password once. Only a scrypt hash is stored, in `$OC_ROOT/secrets/console/admin-password.scrypt`.

1. Open `https://<OC_CONSOLE_HOST>` (for the example config, `https://console.example.com`).
2. Sign in with that password.
3. You land on **Choose your password**. Until you save a new one, every other page redirects back here. Sign out still works.
4. Enter the current password, then a new password twice. It must be at least 12 characters and different from the current one. A few random words is a good choice.
5. After the change, the installer password no longer works. The console signs out every other session.

Change it later from **Change password** in the header. The same rules apply. The audit log records that the password changed, never the value.

Lost the password: on the server, in the Open Cloud directory,

```bash
sudo ./opencloud reset-password
```

That writes a new installer password (shown once) and sets the must-change flag again. The console restarts. Sign in and choose a new password.

## Two-step login

Two-step login adds a 6-digit code from an authenticator app (time-based one-time passwords, RFC 6238: SHA-1, 6 digits, 30 seconds). It is off until you set it up, so a fresh install cannot lock you out at the first sign-in.

### Set it up

1. Sign in and click **Two-step login** in the header (`/account/2fa`).
2. Scan the QR code, or type the setup key shown under it. Any standard TOTP app works.
3. Enter your admin password and the current 6-digit code, then **Turn on two-step login**. Nothing changes until that code is correct.
4. The next page shows **8 recovery codes, once**. Save them in a password manager or on paper. Turning two-step login on ends every other signed-in session.

The QR code and setup key are generated on the server and shown only on that page. They are not written to the audit log. The log records `2fa-enable` and whether it worked.

### Signing in

- The form asks for the password and the code together. The password is checked first, then the code. If either is wrong the message is "Wrong password or code." and there is no session.
- Codes are accepted one 30-second step either side of the server clock. Each code works once. The last used step is stored, so a code cannot be replayed after a restart.
- Failed sign-ins count toward the limits (5 per IP per 5 minutes, 20 per account per 15 minutes), whichever factor was wrong. 20 failures in 15 minutes pauses password sign-in until the window passes.

### Recovery codes

- Type one in the code field instead of a 6-digit code. Dashes and case do not matter. Each works once.
- Only SHA-256 hashes are stored. The **Two-step login** page shows how many unused codes are left.
- When you run low, use the break-glass below and set two-step login up again for a fresh set.

### Lost phone

On the server, as root, in the Open Cloud directory:

```bash
sudo ./opencloud disable-totp
```

`reset-2fa` is the same command. It deletes `$OC_ROOT/secrets/console/totp.json`. The next sign-in needs only the password. Set two-step login up again in the console. No restart is required. Anyone with root can do this. Root already controls the install.

### Where it is stored

`$OC_ROOT/secrets/console/totp.json` holds the secret, the last used step, and the recovery-code hashes. The console user owns it (uid 10001, mode 0600), next to the password hash, inside the root-only `secrets/` directory. It is not encrypted: the console has to read it, and a key on the same disk would not add protection. Backups include it with the rest of `secrets/`.

### What it does not cover

Two-step login protects the browser sign-in. It is not applied to the deployer token, the CloudWatch token, subscriber keys, or Open Bedrock keys. Those are machine credentials on the internal network, each limited to one job.
