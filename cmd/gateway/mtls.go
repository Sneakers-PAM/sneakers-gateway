// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"

	mtls "github.com/Bugs5382/go-mtls"
)

// loadMTLS builds the service's mutual-TLS provider from MTLS_CERT_FILE,
// MTLS_KEY_FILE and MTLS_CA_FILE. With none of them set it returns nil and the
// caller stays on plaintext, which is how the chart's internalTLS switch rolls
// back. A partial setting is an error: half a configuration must not quietly
// become plaintext.
func loadMTLS(getenv func(string) string) (*mtls.Provider, error) {
	cert, key, authority := getenv(mtls.EnvCertFile), getenv(mtls.EnvKeyFile), getenv(mtls.EnvCAFile)
	if cert == "" && key == "" && authority == "" {
		return nil, nil
	}
	var missing []string
	for _, v := range []struct{ name, value string }{{mtls.EnvCertFile, cert}, {mtls.EnvKeyFile, key}, {mtls.EnvCAFile, authority}} {
		if v.value == "" {
			missing = append(missing, v.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("mutual TLS is partly configured, set %v too", missing)
	}
	p, err := mtls.NewProvider(mtls.Files{Cert: cert, Key: key, CA: authority})
	if err != nil {
		return nil, fmt.Errorf("mutual TLS: %w", err)
	}
	return p, nil
}
