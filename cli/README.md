# DNP3-EXTRA Windows diagnostic console

One executable runs either role in a separate Windows process. It uses the existing
OpenDNP3 stack over real TCP or mutual TLS. Controls update simulated database
outputs only. No physical equipment is driven.

## Build and test in the existing Windows workspace

The commands work from any PowerShell directory. Use the workspace drive mapping
visible on your PC if it differs from the verified path below. This build reuses
MSVC, the existing vcpkg toolchain/dependencies and native CMake cache.

```powershell
$repo = 'D:\C drive\User\Desktop\DNP3-EXTRA'
$build = Join-Path $repo 'build-p6b-o1\native'
$python = 'C:\Users\poimu\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& 'C:\Program Files\CMake\bin\cmake.exe' -S (Join-Path $repo 'opendnp3') -B $build -DDNP3_DIAGNOSTIC_CLI=ON -DDNP3_SA_CRYPTO=ON -DDNP3_TLS=ON -DDNP3_TESTS=ON "-DPython3_EXECUTABLE=$python"
& 'C:\Program Files\CMake\bin\cmake.exe' --build $build --config Release --target dnp3-cli unittests integrationtests asiotests --parallel 4
& 'C:\Program Files\CMake\bin\ctest.exe' --test-dir $build -C Release --output-on-failure
$cli = Join-Path $build 'cli\Release\dnp3-cli.exe'
```

Python is used only to orchestrate Windows process tests (standard library).
The process tests run the compiled CLI and check real SOE values, completion and
command invocation counts. Existing Catch tests check malformed messages,
ownership, expiry, replay, tamper and interrupted exchanges. The ASIO suite
receives fresh test certificates without storing private keys in Git.

## Launch two terminals

Use the same `$cli` executable path in each terminal, or the executable in the
release package. For unprotected comparison on localhost:

```powershell
# Terminal 1
& $cli outstation
# Terminal 2
& $cli master
```

Wait for `[LINK] OPEN` on both sides. Default TCP is `127.0.0.1:20000`, addresses
Master 1 and Outstation 10. Both consoles explicitly say **SA DISABLED**.

For SA, provision a unique test profile once. This creates random credentials in
Windows Credential Manager. Use the same profile, association and method on both
peers. Method 68 requires its own provisioning; it is never selected implicitly.

```powershell
& $cli test-provision --test-only --profile lab4 --auth method4
# Terminal 1
& $cli outstation --auth method4 --test-only --profile lab4 --trust-system-time
# Terminal 2
& $cli master --auth method4 --test-only --profile lab4 --trust-system-time
```

`--trust-system-time` explicitly trusts the Windows system clock for credential
expiry. Use a correctly set/synchronized clock. TEST profiles are localhost-only,
with separate Master, Outstation and authority credential namespaces. A separate
child authority uses private local pipes; Master never loads its private signing
key or symmetric Certification Key. This is a test boundary within one Windows
account, not protection against that account's administrator. Credentials expire
in 24 hours initially. No certificate, Update Key or private authority material
is printed. Duplicate owners and cleanup while a peer owns the profile are
rejected. For Method 68, replace `lab4`/`method4` with a fresh name/`method68`
in all three commands. Its first `ruk change` or `ruk add` certifies the chosen
method; the bootstrap Session Keys use the normal AES-256/SHA-256 SA mechanism.

Try these in the Master, waiting for each actual completion:

```text
read 1 2 0 3
crob 0 on
trace on
auth
stats
ruk change operator 1 1 1
crob 0 off direct
ruk verify operator
ruk add guest 0 1 1
user 4
crob 1 on
ruk delete guest 1 1 1
user 2
stats
events
```

`ruk` status arguments are **name, strictly increasing SCS, role number, expiry
days**. The example assumes a fresh profile. `Common` is user 1; `operator` is
user 2 (OPERATOR), `engineer` is user 3 (explicit test PRIVATE policy), and `guest`
is the preprovisioned name for the available fourth slot. For a role-denial test,
`ruk change operator 2 0 1` installs VIEWER; the next control must fail and the
Outstation execution count must not increase. Restore OPERATOR with a higher SCS.
`ruk change-key operator` changes only a key under the existing certified method.
`ruk verify operator` also supports native pending-key recovery. Reopen the same
profile after stopping both programs to exercise persisted credentials. Add
`--aggressive` on both peers to exercise the optional Aggressive path.

After both consoles quit, remove only this profile:

```powershell
& $cli test-cleanup --test-only --profile lab4
```

Use the same `--association` for provisioning, both peers and cleanup if you
changed it. For separately provisioned legacy SA credentials, use
`--auth method4 --credentials <Credential-Manager-prefix> --trust-system-time`;
see the native `WindowsAuthenticationCredentials` contract. The CLI's remote
status/key commands require its explicit TEST authority. A production authority
and provisioning service are outside this console.

## Commands and options

| Master | Effect |
| --- | --- |
| `read <g> <v> [start stop]` | Native all-objects or indexed READ. |
| `scan integrity`, `scan class0` ... `scan class3` | Native class scans; actual measurement/event flags and timestamps. |
| `crob <index> on\|off [sbo\|direct]` | G12 SELECT/OPERATE by default; `direct` uses acknowledged DIRECT_OPERATE. |
| `analog <variation:1..4> <index> <value> [sbo\|direct]` | Native G41 typed command, range-checked. |
| `attr 210`, `attr 254`, `attr 255` | Actual security-stat count and attribute discovery. `attr 209` reports peer response; local Outstation omits unsupported version advertisement. |
| `stats`, `events` | Native G121/G122, including actual wire association, flags and time. |
| `user <number>`, `users`, `auth` | Select task user, inspect durable status and actual session/readiness/exchange/statistics metadata. |
| `assign <group> <class:0..3> <start> <stop>` | Native ASSIGN_CLASS for supported input groups. Use an authorized user such as test user 3 in SA. |
| `unsol on\|off` | Enable/disable all event classes; Outstation must start with `--unsolicited`. |
| `time`, `restart cold\|warm` | G50V1 READ; native restart requests report actual peer support. Automatic NonLAN time sync responds to NEED_TIME. |

| Outstation | Effect |
| --- | --- |
| `set binary\|double\|analog\|counter <index:0..9> <value> [force\|suppress]` | Publish a real native update. Binary accepts on/off; double also accepts intermediate/indeterminate. |
| `show` | Configured point layout and the application's published input values. Use Master READ for native database readback, including output statuses. |
| `restart` | Set native restart IIN. Stop/relaunch to test full restart and credential recovery. Remote cold/warm restart remains unsupported by this simulated application. |
| `status`, `auth`, `users` | Actual link state, simulated execution count, per-association statistics and user/credential metadata. |

Both: `status`, `reconnect`, `trace on|off`, `help`, `quit`, EOF and Ctrl+C.
Wait for a new `OPEN` after reconnect. `[SUBMITTED]` indicates scheduling only;
`[TASK]`/`[RESULT]` and actual point statuses report completion. Read failures can
also appear as IIN request errors. `[EXECUTED]` only follows a native invocation
of the simulated operation. `[DENIED]` reports native authorization denial.
SA trace prints only G120 object identifiers and direction, no APDU hex or
payload. Compatibility trace may print unprotected protocol bytes.

Options: `--host`, `--port`, `--local`, `--remote`, `--auth compat|method4|method68`,
`--association`, `--user`, `--response-ms`, `--reply-ms`, `--renewal-ms`,
`--message-count`, `--trace`, `--aggressive`, `--unsolicited`, `--deny-controls`.
Timeouts/counts must be positive. Default user is 2 for interactive tasks;
startup tasks use Common. No-response typed controls and arbitrary time WRITE
are not exposed. G120V8 remains codec only. See the remote-update report for
SCS wrap, DSA DER interoperability and statistics retention limitations.

## Mutual TLS on port 19999

TLS is independent of SA mode. Supply a trusted CA, local certificate and key,
and the expected peer DNS/IP SAN. Both certificates are verified. The test
command creates short-lived PEM files in a **new** directory with a protected
current-user/SYSTEM ACL; its CA private key is not persisted. Keep these files
outside Git and remove the named test directory after both processes stop.

```powershell
$tls = Join-Path $build 'my-local-tls-test'
& $cli test-tls --test-only --directory $tls
# Terminal 1
& $cli outstation --tls --tls-version 1.3 --ca "$tls\ca.pem" --cert "$tls\server.pem" --key "$tls\server-key.pem" --peer-name master.test --suites TLS_AES_128_GCM_SHA256
# Terminal 2
& $cli master --tls --tls-version 1.3 --ca "$tls\ca.pem" --cert "$tls\client.pem" --key "$tls\client-key.pem" --peer-name outstation.test --suites TLS_AES_128_GCM_SHA256
```

Choose `--tls-version 1.2 --ciphers ECDHE-RSA-AES128-GCM-SHA256` on both for TLS
1.2, or `both` to permit either. Add the SA options independently. Certificate
rotation/revocation scheduling and the product cipher-change timeout are not
implemented by the CLI. SEC-T1-11 remains OPEN: the profile lists TLS 1.2-style
ECDHE names under TLS 1.3. This console uses separate settings as defined by
[RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html) and verifies peer identity
through [OpenSSL verification parameters](https://docs.openssl.org/master/man3/X509_VERIFY_PARAM_set1_host/).

## Windows acceptance evidence

Baseline `33d7994ae551e4f3b30b7ddfb894e59c6b9e336d` passed 714 unit cases /
59,048 assertions and the two SA TCP cases / 240 assertions before edits.
The final Release build (MSVC 17.14, OpenSSL 3.6.5) and CTest both exited **0**.
All **8 CTest entries** passed:

| Suite | Result |
| --- | --- |
| Complete unit suite | 714 cases / 59,048 assertions |
| Complete integration suite, including existing SA TCP | 12 cases / 241 assertions |
| ASIO, including original self-signed and CA TLS tests | 7 cases / 105 assertions |
| Independent-process Windows scenarios | 5 / 5: compatibility, Method 4, Method 68, denials, TLS |

An isolated Windows Ctrl+C check also exited 0 while stdin remained open.
Legacy non-SA integration fixtures explicitly select compatibility; their
original security-default mismatch is not addressed by weakening the library
default or bypassing authentication. The listener smoke check is bounded and
asserts both shutdown calls completed.

| Surface | Locally verified | Remaining boundary |
| --- | --- | --- |
| Measurements/classes/controls | Live binary, double-bit, analog and counter updates, static READ, class 0–3/integrity, timed events, class assignment, unsolicited delivery, CROB and G41 controls, output readback | Tests exercise selected variations; no claim that every profile row was independently verified. |
| Attributes/time/IIN | G0V210 values 0/18, V254/V255 discovery, V209 request-error response, G50V1, native time sync | G0V209 unadvertised; no arbitrary time WRITE or remote cold/warm restart in the simulated Outstation. |
| SA and remote keys | Native Session Key readiness, C/R and Aggressive metadata with actual control completions; G120V10–V15 for Methods 4/68, ADD/CHANGE/DELETE, role and application denials, G121/G122, reconnect and durable process restart | CLI remote provisioning is TEST-only. Existing Catch coverage supplies replay, invalid MAC, malformed G120, expiry and interrupted exchange assertions; no independent device conformance run. |
| TLS | Mutual TLS 1.2/1.3 on 19999, SAN and CA verification, reconnect, SA over TLS, wrong identity, untrusted server/client, expiry, invalid cipher/suite and missing material rejection | Product TLS 1.3 naming conflict, certificate revocation/rotation scheduling and cipher-change timeout remain open. |

These surfaces reuse the existing IEEE 1815-2012 contracts: §5.5 for attributes;
§7.5 and Annex A.45 for SA and remote keys; Table 7-6 and §11.9.10 for security
statistics. See the existing profile and remote-update reports for qualifiers,
role/expiry rules and OPEN decisions. No generated object or protocol state
machine was changed. `IStack::GetAuthenticationStatus` adds a source-compatible
virtual diagnostic method; rebuild binary consumers of the library.

The Windows x64 release archive contains the tested executable, its two OpenSSL
runtime DLLs, this README, process driver, licenses and `REVISION.txt` (Git SHA,
binary hashes and exact source file manifest). It contains no credentials or
certificates. Extract the archive before launching both terminals.
