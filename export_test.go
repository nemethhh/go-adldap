package adldap

import "github.com/nemethhh/go-adldap/internal/conn"

// BinderDescriptionForHost exposes the per-host binder's SPN for tests in the
// adldap_test package. The SPN is not otherwise observable without a KDC.
func BinderDescriptionForHost(cfg Config, host string) string {
	b, err := cfg.binderForHost(host)
	if err != nil {
		return "error: " + err.Error()
	}
	if kb, ok := b.(conn.KerberosBinder); ok {
		return kb.SPNForTest()
	}
	return b.Describe()
}

// BinderRealmForHost exposes the per-host binder's Kerberos realm for tests in
// the adldap_test package. Nothing in BinderDescriptionForHost surfaces the
// realm, and a same-suffix pair of hosts cannot tell "derived from Config.Server"
// apart from "derived from host" — only a caller that can read Realm directly,
// against a cross-suffix host, can pin that.
func BinderRealmForHost(cfg Config, host string) string {
	b, err := cfg.binderForHost(host)
	if err != nil {
		return "error: " + err.Error()
	}
	kb, ok := b.(conn.KerberosBinder)
	if !ok {
		return ""
	}
	return kb.Realm
}
