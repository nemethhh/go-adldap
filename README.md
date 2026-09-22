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
interface whose types are this module's own, so swapping in a fork with SASL
sign+seal and channel binding is a one-package change. A test asserts the
import is there and nowhere else.

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

### Known gap: NTLM and channel binding

Upstream go-ldap sends no channel-binding token, so a domain with
`LdapEnforceChannelBinding` set to `2` rejects an NTLM bind even over TLS. The
classifier spells this out rather than reporting a bare `strongerAuthRequired`,
which sends operators to the LDAP *signing* setting instead.

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
go test ./... -race
```

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
