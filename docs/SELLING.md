# Selling minivpn: vendor guide

This guide is for **you, the vendor**. Don't ship it to customers.

## The business model

minivpn is sold the way OpenVPN Access Server, Pritunl and similar self-hosted VPNs
are sold:

- **Community edition (free, up to 5 devices).** Lets small teams and evaluators try
  it with no friction, and makes it easy to adopt.
- **Business license (paid, per device per year).** Unlocks more devices. It's a
  signed file, so no license server and no phone-home. That suits customers who
  self-host for privacy reasons.

| Plan | Devices | Suggested price |
|---|---|---|
| Community | 5 | free |
| Business 25 | 25 | ₹2,000 / $25 per month, billed yearly |
| Business 100 | 100 | ₹6,500 / $80 per month, billed yearly |
| Enterprise | 500+ | custom, with support SLA |

Comparable products charge about $5–15 per user per month, so a self-hosted price
well below that is an easy pitch to small companies, colleges and clinics.

## Your signing key

`make vendor-key` created two things:

| File | What it is | Where it goes |
|---|---|---|
| `vendor/license-signing.key` | **Private** Ed25519 key that mints licenses | Keep it secret. Back it up offline (a USB stick in a drawer, a password manager). Never commit or email it. |
| `src/license_pubkey.h` | Public key compiled into every `minivpn` binary | Ships in the product; safe to publish |

If you **lose** the private key, you can't issue licenses that existing installs
accept. If it **leaks**, anyone can mint licenses. In that case run
`make vendor-key FORCE=1`, release a new version, and re-issue licenses to paying
customers.

## Issuing a license

```bash
make tools/license-tool
./tools/license-tool sign --customer "Acme Corp" --devices 25 --days 365 > acme.license
./tools/license-tool verify acme.license      # double-check before sending
```

Email `acme.license` to the customer. They install it with
`sudo minivpn-admin license install acme.license` or through the dashboard. Renewals are
the same command with a new `--days`. Upgrades are the same command with a new `--devices`.

Keep a record (a spreadsheet is fine) of license_id, customer, devices, expiry and
amount paid. The license id is printed in the file and shown in the customer's dashboard,
which makes support conversations easy.

## Releasing a version

```bash
make clean && make && make test && sudo make integration
make deb            # -> build/minivpn_<version>_amd64.deb
```

Set `DEB_MAINTAINER="Your Company <support@yourdomain>"` when building, and update the
`Homepage` in `packaging/build-deb.sh` and the copyright holder in `LICENSE`.

## What customers are paying for (your pitch)

1. **Their own server, their own data.** No third-party relay sees traffic or metadata.
2. **One-minute onboarding.** `minivpn-admin add laptop`, send the file, done.
3. **Instant offboarding.** Revoking a device cuts it off in under a second, and the
   audit log shows who did it.
4. **Modern cryptography.** X25519, ChaCha20-Poly1305, forward secrecy, automatic
   rekeying. These are the same primitives WireGuard and TLS 1.3 use.
5. **No per-seat cloud lock-in.** A license file works offline, forever, until it expires.

## Honest limitations to fix before selling to large customers

- **Linux clients only.** Windows and macOS clients are the biggest gap. They would be
  wrappers around Wintun and utun, plus a tray app.
- **IPv4 only inside the tunnel.**
- **No SSO.** A single admin account. Add OIDC (Google / Microsoft login) for Business+.
- **No independent security audit yet.** Get one before marketing to regulated industries.
- **Licensing is honour-plus-signature.** A determined customer could patch the binary.
  That's normal for self-hosted software; price and support are what keep people paying.
