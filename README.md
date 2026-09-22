# go-adldap

Manages Active Directory over LDAP, directly from Go — no PowerShell, no RSAT,
no Windows host anywhere in the chain. The provider binary and TCP 636 are the
whole runtime requirement.

It satisfies the same [`adcore.Directory`](https://github.com/nemethhh/go-adcore)
contract as [`go-adpwsh`](https://github.com/nemethhh/go-adpwsh), so a consumer
written against one works against the other unchanged.

> **Status:** the connection layer. Dial, TLS, three bind mechanisms, a bounded
> pool, error classification and DC pinning are done and tested. The per-class
> CRUD sub-directories are not yet implemented, so `Directory()` returns a value
> whose `OU`, `Group` and `User` fields are still nil.

## Design

**TLS is mandatory.** `ldaps` on 636 or `starttls` on 389. There is no plain
mode: a simple bind over cleartext 389 sends the password in the clear, and a
domain with LDAP signing required refuses it anyway.

**One DC, pinned for the client's lifetime.** `Config.Server` names it and
there is deliberately no discovery. A create that lands on DC-A and a read-back
that hits DC-B reports "not found".

**Exactly one auth block.** `Simple`, `Kerberos` or `NTLM` — never zero, never
two. Guessing would authenticate as the wrong identity.

**go-ldap lives in exactly one package.** `internal/conn` adapts it behind an
interface whose types are this module's own — which is why swapping
`jcmturner/gokrb5` for `oiweiwei/gokrb5.fork` to add channel binding touched
only this package. A test asserts the imports are there and nowhere else.
GSSAPI sign/seal was considered and declined: TLS already protects the
connection, so a second encryption layer buys nothing.

**All attribute values are `[][]byte`.** `objectGUID`, `objectSid` and
`nTSecurityDescriptor` are binary; reading them back as strings corrupts them.

## Authenticating

The intended path is a ticket the operator obtained themselves, so no
credential goes in Terraform configuration:

```sh
KRB5CCNAME=FILE:/tmp/krb5cc_tf kinit svc_tf@CORP.LOCAL
```

The `FILE:` prefix matters. gokrb5 reads a credential cache with `os.ReadFile`,
so only file caches work — and `KEYRING` (RHEL, Fedora with sssd) and `KCM`
(Ubuntu with sssd-kcm) are the platform defaults. Naming one of those produces
an error that says exactly this rather than "no ticket found".

This is the Linux and macOS path. Windows keeps credentials in the LSA with no
readable cache, so a Windows operator uses `simple` or `ntlm` until an SSPI
client lands behind the `conn` seam.

Where `kinit` was never installed — CI, a scratch container — a credential can
be supplied instead:

```go
Kerberos: &adldap.KerberosAuth{
    Username: "svc_tf",
    Password: adcore.NewSecret(os.Getenv("AD_PASSWORD")),
}
```

The realm defaults to the server's domain suffix uppercased, and with no
`/etc/krb5.conf` present a minimal one is synthesized naming `Config.Server` as
the KDC. At most one of `CCachePath`, `Keytab` and `Password` may be set.

### Channel binding

Every Kerberos bind carries a `tls-server-end-point` channel-binding token, so
a domain with `LdapEnforceChannelBinding = 2` — required by the CIS Benchmark
and the DISA STIG — accepts it. The token is computed from the certificate the
connection actually negotiated, and is sent unconditionally, which is what a
Windows client does.

**NTLM is the remaining gap.** Upstream go-ldap sends no token, so `ntlm` is
still refused where the policy is `2`, with `data 80090346` and no mention of
channel binding. Use `kerberos` or `simple` there. This is a library choice
rather than a protocol limit — the AV_PAIR exists — and is recorded as future
work.

## Errors

An LDAP failure becomes the same `adcore.Kind` the PowerShell backend would
produce for the same condition. That works because AD prefixes its diagnostic
messages with the very Win32 codes the other backend classifies on —
`0000208D: NameErr:` is `ERROR_DS_OBJ_NOT_FOUND` — so both call
`adcore.ClassifyCode` and read one table.

Only `KindTransient` is ever retried. A cancellation is `KindTransport`: the
request may already have reached the DC, so re-issuing it could duplicate a
side effect.

## Testing

`internal/adtest` runs an in-process LDAP server on a real socket with a
certificate the client verifies, so a wrong attribute encoding or a mis-sent
control fails in CI rather than first on a lab domain.

```sh
make check
```

That is build, `go vet`, a gofmt check and `go test ./... -race` — the same
target CI runs, so a red build reproduces with one command rather than by
reading the workflow. `-race` is not decoration: the pool hands connections to
callers concurrently and each one runs a `Binder`, so a race here is a race on
someone's credentials.

```sh
make audit
```

`go mod tidy -diff` and `govulncheck`. A scheduled run does this weekly as well
as on every push, because a vulnerability appears in a dependency without
anyone touching this repository — and the Kerberos library is a fork of an
upstream that stopped accepting commits in 2022, so nothing else would say so.

## Licence

MIT. See [LICENSE](LICENSE).

## The cross-backend differential suite

`acc_differential_test.go` is behind the `acc` build tag and
`AD_ACC_DIFFERENTIAL=1`. It creates one object of each class through this
backend, reads it back through **both** this one and `go-adpwsh`, and requires
the decoded models to be identical. The conformance suite proves each backend
satisfies the contract; only this proves they agree.

That is why `go-adpwsh` appears in `go.mod`. It is a **test** dependency of
this one file and nothing in the runtime path imports it — the invariant that
`go-ldap` lives only in `internal/conn` is unaffected, and so is the rule that
no Terraform package enters either library.

Its first run found three real divergences, all now fixed: the `$` on a
computer's and a gMSA's `SamAccountName`, `GenericRead` rendered as its four
constituent bits, and an absent multi-valued attribute decoding as an empty
slice on one side and nil on the other.
