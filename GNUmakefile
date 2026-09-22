default: check

# Every Go file this repository owns. There is no vendored clone to prune here
# — unlike the provider repo, where a bare gofmt walks 24,000 files that are
# not ours — so the find is a plain one. Kept as a variable anyway so fmt and
# fmt-check cannot drift apart in what they look at.
GOFILES := $(shell find . -path ./.git -prune -o -name '*.go' -print)

# Pinned rather than added to go.mod: govulncheck is not imported by the
# library, and its dependency tree has no business in the graph a consumer
# resolves. Same reasoning the provider repo applies to its own tools.
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0

.PHONY: default build test check audit fmt fmt-check vet tidy-check vuln clean

build:
	go build ./...

# -race is not optional for this library. Pool.Acquire hands connections to
# callers concurrently and each one runs a Binder, so a data race here is a
# race on someone's credentials. The README tells developers to run it this
# way; CI running the identical command is what keeps the two honest.
#
# acc_differential_test.go sits behind the `acc` build tag and needs a real
# domain plus go-adpwsh, so `./...` excludes it without any flag here.
test:
	go test ./... -race -timeout 5m

fmt:
	gofmt -w $(GOFILES)

fmt-check:
	@unformatted="$$(gofmt -l $(GOFILES))"; \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi

vet:
	go vet ./...

# What CI runs, in the order CI runs it, so a red build can be reproduced with
# one command instead of by reading the workflow.
check: build vet fmt-check test

# go.mod and go.sum must already be what `go mod tidy` would produce. Without
# this a stale requirement survives indefinitely: the build succeeds either
# way, and the drift only surfaces when a consumer resolves a different graph
# than the one CI tested.
tidy-check:
	go mod tidy -diff

# The dependency tree must carry no known vulnerability.
#
# This matters more here than in most repositories. The Kerberos library is
# github.com/oiweiwei/gokrb5.fork, adopted because its upstream — jcmturner/gokrb5
# — stopped accepting commits in 2022. A fork of an abandoned cryptographic
# library will not announce a CVE in a release note anybody watches, so a
# scheduled scan is the only thing standing between this module and a
# vulnerability nobody told it about. The audit workflow runs this weekly for
# exactly that reason, not only on push.
vuln:
	go run $(GOVULNCHECK) ./...

audit: tidy-check vuln

clean:
	go clean -testcache
