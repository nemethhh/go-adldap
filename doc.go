// Package adldap manages Active Directory over LDAP, directly from Go, with no
// PowerShell and no Windows host anywhere in the chain.
//
// It satisfies the same adcore.Directory contract as go-adpwsh, so a consumer
// written against one works against the other unchanged. TLS is mandatory:
// LDAPS on 636 or StartTLS on 389. Plain LDAP is not offered, because a simple
// bind over it sends the password in clear text and a domain with LDAP signing
// required refuses it anyway.
package adldap
