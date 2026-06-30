# Handover: Add client certificate (mTLS) support to the `vault` KMS type

## Why

The `vault` KMS type already supports a custom CA cert via `vaultCAFromSecret` for
server certificate verification. It does not support presenting a client certificate,
making it impossible to use mTLS to a Vault-compatible server.

The `vaulttokens` type has full mTLS support (`vaultClientCertFromSecret` +
`vaultClientCertKeyFromSecret`) but requires a per-tenant Kubernetes Secret for the
Vault token — one Secret per PVC namespace. In clusters with thousands of workspace
namespaces this is impractical.

The `vault` type uses Kubernetes SA token authentication instead (no per-namespace
Secret needed), but cannot do mTLS. This change adds the missing client cert support
to `vault`, making it the correct type for mTLS deployments that use Kubernetes SA auth.

## Upstream motivation

This is a purely additive feature that closes a symmetric gap: `vaultCAFromSecret`
(already in `vault`) handles the server side of TLS; `vaultClientCertFromSecret` and
`vaultClientCertKeyFromSecret` (this change) handle the client side. The pattern,
config key names, and implementation are already established in `vaulttokens` — this
change ports them to the base `vault` type using the same credential source
(`args.Secrets`, the CSI node-stage secret map) that `vaultCAFromSecret` already uses.

Upstream PR title: *"kms: add client certificate support to the vault KMS type"*

## Credential source: K8s Secret API — not `args.Secrets`

**This is the most important thing to get right.**

In `vaulttokens`, `vaultCAFromSecret`, `vaultClientCertFromSecret`, and
`vaultClientCertKeyFromSecret` are **Kubernetes Secret names**. The code calls
`k8s.GetSecret(secretName, namespace)` to fetch them at runtime. This is what
allows the config to say `"vaultCAFromSecret": "istio-ca-root-cert-secret"` and
have the code look up a Secret named `istio-ca-root-cert-secret` in Kubernetes.

The `vault` type currently reads `vaultCAFromSecret` differently — as a **key
name within `args.Secrets`** (the flat map from the CSI node-stage Secret). This
is the wrong model for this change.

**The implementation must use `k8s.GetSecret`**, exactly as `vaulttokens` does.
The only difference from `vaulttokens` is that `vault` has no tenant namespace —
it looks up Secrets only in the CSI pod namespace (`os.Getenv("POD_NAMESPACE")`,
which is `rook-ceph`).

### Required import addition

`internal/kms/vault.go` currently does not import `k8s`. Add:

```go
"github.com/ceph/ceph-csi/internal/util/k8s"
```

Also add (already used in `vault_tokens.go` for the same pattern):
```go
apierrs "k8s.io/apimachinery/pkg/api/errors"
"os"
```

Check the existing imports in `vault.go` — `"os"` is already imported (used in
`Destroy()`). `apierrs` and `k8s` need to be added.

## File to change: `internal/kms/vault.go`

### Change 1: Update the `Destroy()` method (line 158)

The existing `Destroy()` only removes the CA cert temp file. Extend it to also
remove the client cert and key temp files when present.

**Current** (`internal/kms/vault.go:158-167`):
```go
func (vc *vaultConnection) Destroy() {
	if vc.vaultConfig != nil {
		tmpFile, ok := vc.vaultConfig[api.EnvVaultCACert]
		if ok {
			//nolint:forcetypeassert,errcheck // ignore error on failure to remove tmpfile
			_ = os.Remove(tmpFile.(string))
		}
	}
}
```

**After**:
```go
func (vc *vaultConnection) Destroy() {
	if vc.vaultConfig == nil {
		return
	}
	for _, key := range []string{api.EnvVaultCACert, api.EnvVaultClientCert, api.EnvVaultClientKey} {
		if tmpFile, ok := vc.vaultConfig[key]; ok {
			//nolint:forcetypeassert,errcheck // ignore error on failure to remove tmpfile
			_ = os.Remove(tmpFile.(string))
		}
	}
}
```

### Change 2: Extend `initCertificates()` (line 299)

**Replace the entire function** with one that uses `k8s.GetSecret` for all three
cert config options, mirroring `vaultTenantConnection.initCertificates` in
`vault_tokens.go` but without the tenant namespace — only the CSI pod namespace
(`rook-ceph`) is used.

Field names within the Secrets are fixed:
- CA cert Secret: field `"cert"`
- Client cert Secret: field `"cert"`  
- Client key Secret: field `"key"`

This matches the field names used by `vaulttokens` and by the
`esm-certificates-manager-chart` sync jobs.

```go
func (vc *vaultConnection) initCertificates(config map[string]any, secrets map[string]string) error {
	vaultConfig := make(map[string]any)
	csiNamespace := os.Getenv("POD_NAMESPACE")

	vaultCAFromSecret := "" // optional
	err := setConfigString(&vaultCAFromSecret, config, "vaultCAFromSecret")
	if errors.Is(err, errConfigOptionInvalid) {
		return err
	}
	if vaultCAFromSecret != "" {
		cert, err := k8s.GetSecret(vaultCAFromSecret, csiNamespace)
		if err != nil {
			return fmt.Errorf("failed to get CA certificate from secret %s: %w", vaultCAFromSecret, err)
		}
		caPEM, ok := cert["cert"]
		if !ok {
			return fmt.Errorf("missing \"cert\" field in secret %s", vaultCAFromSecret)
		}
		tf, err := file.CreateTempFile("vault-ca-cert", caPEM)
		if err != nil {
			return fmt.Errorf("failed to create temporary file for Vault CA: %w", err)
		}
		vaultConfig[api.EnvVaultCACert] = tf.Name()
	}

	vaultClientCertFromSecret := "" // optional
	err = setConfigString(&vaultClientCertFromSecret, config, "vaultClientCertFromSecret")
	if errors.Is(err, errConfigOptionInvalid) {
		return err
	}
	if vaultClientCertFromSecret != "" {
		certSecret, err := k8s.GetSecret(vaultClientCertFromSecret, csiNamespace)
		if err != nil {
			return fmt.Errorf("failed to get client certificate from secret %s: %w", vaultClientCertFromSecret, err)
		}
		certPEM, ok := certSecret["cert"]
		if !ok {
			return fmt.Errorf("missing \"cert\" field in secret %s", vaultClientCertFromSecret)
		}
		tf, err := file.CreateTempFile("vault-client-cert", certPEM)
		if err != nil {
			return fmt.Errorf("failed to create temporary file for Vault client certificate: %w", err)
		}
		vaultConfig[api.EnvVaultClientCert] = tf.Name()
	}

	vaultClientCertKeyFromSecret := "" // optional
	err = setConfigString(&vaultClientCertKeyFromSecret, config, "vaultClientCertKeyFromSecret")
	if errors.Is(err, errConfigOptionInvalid) {
		return err
	}
	if vaultClientCertKeyFromSecret != "" {
		keySecret, err := k8s.GetSecret(vaultClientCertKeyFromSecret, csiNamespace)
		if err != nil {
			return fmt.Errorf("failed to get client certificate key from secret %s: %w", vaultClientCertKeyFromSecret, err)
		}
		keyPEM, ok := keySecret["key"]
		if !ok {
			return fmt.Errorf("missing \"key\" field in secret %s", vaultClientCertKeyFromSecret)
		}
		tf, err := file.CreateTempFile("vault-client-cert-key", keyPEM)
		if err != nil {
			return fmt.Errorf("failed to create temporary file for Vault client certificate key: %w", err)
		}
		vaultConfig[api.EnvVaultClientKey] = tf.Name()
	}

	maps.Copy(vc.vaultConfig, vaultConfig)

	return nil
}
```

**Note**: the existing `secrets map[string]string` parameter is kept in the
signature to avoid changing the call site in `initVaultKMS`. The parameter is
simply unused after this change. If the reviewer asks to remove it, the call site
at `vault.go:369` must be updated to `kms.initCertificates(args.Config, nil)` or
the signature changed to `initCertificates(config map[string]any) error` with
the call site updated accordingly. Either is acceptable — follow reviewer guidance.

### Change 3: Update the KMS config doc comment (line 58)

Add the two new fields to the example JSON in the `VaultKMS` block comment so
they appear in documentation:

```go
/*
VaultKMS represents a Hashicorp Vault KMS configuration

Example JSON structure in the KMS config is,
{
	"local_vault_unique_identifier": {
		"encryptionKMSType": "vault",
		"vaultAddress": "https://127.0.0.1:8500",
		"vaultAuthPath": "/v1/auth/kubernetes/login",
		"vaultRole": "csi-kubernetes",
		"vaultNamespace": "",
		"vaultPassphraseRoot": "/v1/secret",
		"vaultPassphrasePath": "",
		"vaultCAVerify": true,
		"vaultCAFromSecret": "vault-ca-secret",
		"vaultClientCertFromSecret": "vault-client-cert-secret",
		"vaultClientCertKeyFromSecret": "vault-client-cert-secret"
	},
	...
}.

"vaultCAFromSecret", "vaultClientCertFromSecret", and "vaultClientCertKeyFromSecret"
are Kubernetes Secret names in the CSI pod namespace. The CA cert is read from
the "cert" field of the named Secret; the client cert from the "cert" field and
the client key from the "key" field of their respective Secrets (cert and key
may be in the same Secret or different Secrets).
*/
```

## Test to add: `internal/kms/vault_test.go`

Add `TestInitCertificates` to `vault_test.go`. The test must not require a running
cluster — mock the K8s API calls by noting that `k8s.GetSecret` will fail without
a cluster, so tests should verify config parsing and error paths, and use
table-driven subtests for the error cases. For the happy path (actual temp file
creation), tests can only verify the function returns no error when given valid
config pointing at real Secrets — skip if no cluster available, using the same
`if true { return }` pattern already used in `TestInitVaultTokensKMS`.

Minimum test cases to add:

```go
func TestInitCertificatesConfigParsing(t *testing.T) {
	t.Parallel()

	t.Run("invalid config type returns error", func(t *testing.T) {
		t.Parallel()
		vc := &vaultConnection{vaultConfig: make(map[string]any)}
		config := map[string]any{"vaultCAFromSecret": 12345} // wrong type
		err := vc.initCertificates(config, nil)
		require.Error(t, err)
		require.True(t, errors.Is(err, errConfigOptionInvalid))
	})

	t.Run("empty config is a no-op", func(t *testing.T) {
		t.Parallel()
		vc := &vaultConnection{vaultConfig: make(map[string]any)}
		err := vc.initCertificates(map[string]any{}, nil)
		require.NoError(t, err)
		_, hasCA := vc.vaultConfig[api.EnvVaultCACert]
		require.False(t, hasCA)
		_, hasCert := vc.vaultConfig[api.EnvVaultClientCert]
		require.False(t, hasCert)
		_, hasKey := vc.vaultConfig[api.EnvVaultClientKey]
		require.False(t, hasKey)
	})
}

func TestDestroyRemovesAllTempFiles(t *testing.T) {
	t.Parallel()

	// Create real temp files to simulate what initCertificates produces
	caFile, err := file.CreateTempFile("vault-ca-cert", "fake-ca")
	require.NoError(t, err)
	certFile, err := file.CreateTempFile("vault-client-cert", "fake-cert")
	require.NoError(t, err)
	keyFile, err := file.CreateTempFile("vault-client-cert-key", "fake-key")
	require.NoError(t, err)

	vc := &vaultConnection{
		vaultConfig: map[string]any{
			api.EnvVaultCACert:    caFile.Name(),
			api.EnvVaultClientCert: certFile.Name(),
			api.EnvVaultClientKey: keyFile.Name(),
		},
	}
	vc.Destroy()

	_, err = os.Stat(caFile.Name())
	require.True(t, os.IsNotExist(err), "CA cert temp file should be removed")
	_, err = os.Stat(certFile.Name())
	require.True(t, os.IsNotExist(err), "client cert temp file should be removed")
	_, err = os.Stat(keyFile.Name())
	require.True(t, os.IsNotExist(err), "client key temp file should be removed")
}
```

Add `"os"` and `"github.com/ceph/ceph-csi/internal/util/file"` to imports in
`vault_test.go` if not already present.

## Running the tests

```bash
# Unit tests for the kms package only (no cluster needed)
go test -v github.com/ceph/ceph-csi/internal/kms

# Or via make
./scripts/test-go.sh
```

## How this is used in our deployment (context only — no changes needed here)

After this change, the `vault` KMS type config in `csi-kms-connection-details`
in `rook-ceph` becomes identical in structure to the current `vaulttokens` config,
minus the token fields:

```json
{
  "appstudio-cmk": {
    "encryptionKMSType": "vault",
    "vaultAddress": "https://key-manager.webide-system.svc.cluster.local:8443",
    "vaultAuthPath": "/v1/auth/kubernetes/login",
    "vaultBackend": "kv",
    "vaultPassphraseRoot": "/v1/ceph-csi-overlay",
    "vaultPassphrasePath": "ceph-csi/",
    "vaultRole": "ceph-csi",
    "vaultCAFromSecret": "istio-ca-root-cert-secret",
    "vaultClientCertFromSecret": "csi-rbdplugin-vault-client-tls-renamed",
    "vaultClientCertKeyFromSecret": "csi-rbdplugin-vault-client-tls-renamed"
  }
}
```

`"istio-ca-root-cert-secret"` and `"csi-rbdplugin-vault-client-tls-renamed"` are
**Kubernetes Secret names** in the `rook-ceph` namespace (the CSI pod namespace).
These are the same Secrets already created and managed by `esm-certificates-manager-chart`
for the current `vaulttokens` setup — no changes needed to those Secrets or to
that chart.

The `rook-csi-rbd-node` and `rook-csi-rbd-provisioner` Secrets do **not** need
modification — unlike what was previously described in this handover, they are
not involved in cert resolution at all.

## What does NOT need to change

- `vaultTenantConnection.initCertificates` in `vault_tokens.go` — unchanged
- `initVaultKMS` call site in `vault.go:369` — already calls
  `kms.initCertificates(args.Config, args.Secrets)`, the `secrets` parameter
  simply becomes unused after this change
- `ProviderInitArgs`, `GetKMS`, or any caller
- Any vendor files — `api.EnvVaultClientCert` and `api.EnvVaultClientKey` are
  already defined in `vendor/github.com/hashicorp/vault/api/client.go:54-55`
- `esm-certificates-manager-chart` — the existing Secrets it manages are reused
  as-is
- `rook-csi-rbd-node` / `rook-csi-rbd-provisioner` Secrets — not involved
