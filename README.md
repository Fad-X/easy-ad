# easy-ad

**Fast, automated Active Directory enumeration and attack-path scanner** — a
Rust CLI inspired by NetExec (nxc). One command takes you from host discovery
through credential validation, BloodHound CE collection and attack-path checks.

`easy-ad` prefers **native Rust protocol clients** and only falls back to
invoking `nxc` for checks where a native implementation is not yet feasible
(e.g. Kerberos ticket acquisition, coercion triggers, gMSA blob decryption).
If `nxc` is missing, `easy-ad` offers to install it automatically
(`pipx` → `pip3` → `git clone`).

> ⚠️ Only run `easy-ad` against systems you own or are explicitly authorized
> to test. It performs active scanning and credential validation.

---

## Features

| Capability | Engine | Notes |
|---|---|---|
| Host discovery (CIDR / IP lists / hostnames) | native (`ipnet` + Tokio) | TCP probes on 10 AD-relevant ports, thread-bounded |
| Domain Controller auto-discovery | native (`hickory-resolver`) | DNS SRV `_ldap._tcp.dc._msdcs.<domain>` |
| LDAP bind + full directory collection | native (`ldap3`) | users, groups, computers, OUs, GPOs, trusts, password policy |
| Kerberoastable / AS-REP roastable / pre2k / gMSA discovery | native LDAP filters | exact nxc-compatible filters |
| SMB access validation | native (`smb` crate, SMB2/3) | IPC$ tree connect per host |
| SMB share + permission enumeration | nxc `--shares` | parsed into structured perms table |
| WinRM access check + command exec | native (`winrm-rs`) | NTLMv2 / Basic |
| MSSQL access + `SELECT @@VERSION` | native (`tiberius`) on Windows; nxc elsewhere | TDS 7.2+, async |
| RDP reachability | native | real X.224 Connection Request/Confirm exchange |
| Kerberoasting / AS-REP roasting (hash capture) | nxc fallback | hashes written to the output dir |
| Pre2k TGT attempts | nxc `pre2k` module | |
| Coercion scan (PetitPotam, DFSCoerce, PrinterBug, MSEven, ShadowCoerce) | nxc `coerce_plus` module | optional listener IP |
| gMSA password extraction | nxc `--gmsa` | |
| BloodHound CE collection | native | BH CE v5 JSON files + import-ready ZIP |
| JSON + PDF reports | native | PDF generated in pure Rust, zero external deps |
| Audit logging | `tracing` | every finding logged to `easy-ad.log` |

### Deliberate nxc fallbacks

Per the design goal, `easy-ad` shells out to `nxc` only where a native
implementation would require a full extra protocol stack:

- Kerberos ticket acquisition (TGS/AS-REQ) → `nxc ldap --kerberoasting / --asreproast`
- Pre-2k default machine-password TGT attempts → `nxc ldap -M pre2k`
- Coercion triggering → `nxc smb -M coerce_plus`
- gMSA `msDS-ManagedPassword` blob decryption → `nxc ldap --gmsa`
- Share ACL enumeration with NTLM-hash auth → `nxc smb --shares -H`
- RDP credential validation (CredSSP/NLA) → `nxc rdp`
- MSSQL authentication on non-Windows platforms (tiberius' SSPI-based
  Windows auth is Windows-only) → `nxc mssql`

If `nxc` is absent you are prompted to auto-install it
(`pipx install netexec` → `pip3 install netexec` →
`git clone https://github.com/Pennyw0rth/NetExec`). Use `--no-nxc-install` to
disable this; native checks continue either way.

SMB access verification with NTLM-hash credentials also goes through `nxc`
(`nxc smb -H`): the native `smb` code path is password-only.

When `-k/--kerberos` is passed, `easy-ad` first probes the KDC (TCP 88 on the
DC). If no KDC is reachable it warns loudly and records a `kerberos/kdc`
finding, because the native protocol clients would otherwise silently fall
back to NTLM while the report claims Kerberos was used.

## Running the Windows build

Binaries built for `x86_64-pc-windows-gnullvm` link the UCRT dynamically, so
the release executable needs a few DLLs next to it. Copy these into the same
directory as `easy-ad.exe` (a ready-to-run layout ships in `dist/`):

- `libunwind.dll` — from the toolchain's `lib/rustlib/x86_64-pc-windows-gnullvm/bin/`
- `ucrtbase.dll` and the `api-ms-win-crt-*.dll` forwarders — from `C:\Windows\System32\downlevel\`

The same rule applies to any helper `*.exe` on PATH that `easy-ad` shells out
to (e.g. an `nxc.exe` shim): keep the same DLL set beside the helper, not just
beside `easy-ad.exe`, because Windows resolves DLLs from the *helper's* own
directory first.

### WSL-based nxc shim

On Windows hosts without a native NetExec install, a tiny forwarding shim
(the companion `nxc-shim` crate) can expose the WSL Kali `nxc` as `nxc.exe`
on PATH: it spawns `wsl.exe -d kali-linux -- nxc <args>`, captures both
output streams explicitly (inheriting stdio loses output when the parent
captures the shim via pipes), forwards them, and exits with nxc's status
code. Put the shim's directory at the front of PATH so `easy-ad`'s
`find_nxc` locates it, and keep the same UCRT DLL set next to the shim.

## Build

Requires a stable Rust toolchain (1.98+, edition 2021).

```bash
cargo build --release
# binary: target/<triple>/release/easy-ad(.exe)
```

Platform notes:

- **Linux**: the LDAPS/TLS backend links against OpenSSL, so the system
  headers are needed (`libssl-dev` on Debian/Kali, `openssl-devel` on
  Fedora). Everything else is pure Rust.
- **Windows (MSVC or llvm-mingw targets)**: links the UCRT dynamically — see
  the next section for the DLLs to ship next to the executable.

## Usage

```bash
# Full automated scan against a subnet
easy-ad -t 192.168.1.0/24 -d corp.local -u admin -p 'P@ssw0rd' --all-checks --bloodhound

# Kerberoast a single DC with hash auth
easy-ad -t 10.0.0.5 -d corp.local -u admin \
    --hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 \
    --kerberoast --asreproast

# BloodHound collection only via Kerberos
easy-ad -t dc01.corp.local -d CORP.LOCAL -u svc_recon -k --bloodhound --bh-output ./bh-data

# From a config file (CLI flags win over the file)
easy-ad --config config.example.toml
```

### CLI flags

```
-t, --target <T>      Target IP, comma-separated IPs, CIDR, or hostname (required)
-d, --domain <D>      AD domain name (required)
-u, --username <U>    Username
-p, --password <P>    Password
    --hash <H>        NTLM hash (LM:NT or bare NT) - alternative to --password
-k, --kerberos        Use Kerberos authentication where supported
    --dc <IP>         Domain Controller IP (auto-discovered if omitted)
    --bloodhound      Enable BloodHound CE data collection
    --bh-output <D>   BloodHound output directory
    --all-checks      Run every attack-path and protocol check
    --kerberoast      Kerberoasting
    --asreproast      AS-REP Roasting
    --pre2k           Pre-Windows-2000 computer account check
    --coerce          Coercion vulnerability scan (coerce_plus)
    --gmsa            gMSA discovery + password extraction
    --shares          SMB share enumeration + permissions
    --winrm           WinRM access check
    --rdp             RDP reachability check
    --mssql           MSSQL access check
-o, --output <D>      Output directory (default: ./easy-ad-output)
    --format <F>      json | pdf | both (default: both)
-T, --threads <N>     Concurrent threads (default: 10)
    --timeout <S>     Connection timeout seconds (default: 10)
    --include-hashes  Include raw hashes/tickets in the PDF (always on disk)
-v, --verbose         Verbose output
    --no-nxc-install  Disable the NetExec auto-install prompt
    --config <FILE>   TOML config file; CLI flags take precedence
```

## Output

Everything lands in `./easy-ad-output/<timestamp>/`:

| File | Contents |
|---|---|
| `hosts.json` | every scanned host + open AD ports |
| `users.json` | parsed, deduplicated accounts (user/computer/service/gMSA) |
| `shares.json` | share permission table (read/write/execute per share) |
| `attack_paths.json` | vulnerable findings only (roastable, coercion, gMSA, ...) |
| `credentials.json` | validated credentials (username, auth type, protocol) |
| `findings.json` | all findings (target, protocol, check, status, severity, details, timestamp) |
| `easy-ad-report.pdf` | human-readable report: exec summary, hosts, attack paths, shares, accounts |
| `kerberoast.hashes` / `asreproast.hashes` | crackable captures (when the checks run) |
| `bloodhound/*.json` + `*_bloodhound.zip` | BloodHound CE import package (with `--bloodhound`) |
| `easy-ad.log` | full audit log of the run |

## Architecture

```
src/
├── main.rs                 # CLI entry, orchestration pipeline
├── cli.rs                  # clap definitions + TOML config overlay
├── auth.rs                 # password / NTLM hash / Kerberos credential handling
├── findings.rs             # structured finding model + thread-safe accumulator
├── nxc.rs                  # nxc detection, auto-install, invocation
├── scanner/
│   ├── mod.rs              # shared ScanContext
│   ├── smb.rs              # native SMB2/3 access checks + nxc share parsing
│   ├── ldap.rs             # ldap3 client, query builders, directory collection
│   ├── winrm.rs            # winrm-rs shell + command execution
│   ├── rdp.rs              # native X.224 RDP probe
│   └── mssql.rs            # tiberius TDS auth + fingerprinting
├── attack_paths/
│   ├── mod.rs              # shared attack context
│   ├── kerberoast.rs       # SPN discovery (native) + TGS capture (nxc)
│   ├── asreproast.rs       # DONT_REQ_PREAUTH discovery + AS-REP capture (nxc)
│   ├── pre2k.rs            # pre-2k computer accounts + TGT attempts (nxc)
│   ├── coercion.rs         # coerce_plus wrapper (nxc)
│   └── gmsa.rs             # gMSA discovery + extraction (nxc)
├── bloodhound/
│   ├── mod.rs              # BH CE v5 JSON builders (SID/filetime parsing)
│   └── ingest.rs           # ZIP packaging for BH CE import
├── report/
│   ├── mod.rs              # report orchestration
│   ├── json.rs             # per-category JSON outputs
│   └── pdf.rs              # dependency-free PDF generator
└── discovery/
    ├── mod.rs              # CIDR expansion, port probing, DC discovery
    └── parser.rs           # username classification + share output parsing
```

## Testing

```bash
cargo test            # 41 unit tests: query builders, parsers, SID/filetime,
                      # PDF serialization, CLI/config merge, share parsing
```

Integration tests (ignored by default) run against a live domain, e.g. a
Dockerized Samba AD DC:

```bash
export EASY_AD_TEST_DC=127.0.0.1 EASY_AD_TEST_DOMAIN=example.test EASY_AD_TEST_PASS='Passw0rd!'
cargo test --test integration -- --include-ignored
```

## Real-world validation

Validated against a live HackTheBox lab box (Windows Server 2016,
workgroup, no LDAP/Kerberos): both password and pass-the-hash credential
validation over SMB/MSSQL/RDP matched the NetExec reference results exactly;
AD-only checks degraded gracefully with explicit findings instead of silent
skips. Bugs found and fixed during that pass: the RDP X.224 probe length
indicator, MSSQL Windows-authentication mode, NTLM-hash SMB verification via
nxc, and the Kerberos KDC preflight described above.

## Error handling

- Network errors are logged and the scan continues to the next target.
- Authentication failures are reported as `access_denied` findings per protocol.
- Missing dependencies (nxc) trigger the auto-installer or a clear message.
- Partial results are always written — a failed check never discards
  collected data.

## License

MIT — see `Cargo.toml`. For authorized security testing only.
