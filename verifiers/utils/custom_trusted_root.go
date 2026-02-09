package utils

import (
	"fmt"

	sigstoreRoot "github.com/sigstore/sigstore-go/pkg/root"
	sigstoreTUF "github.com/sigstore/sigstore-go/pkg/tuf"
)

// GetCustomTrustedRoot loads a Sigstore trusted root from either a local file
// or a custom TUF repository URL. Exactly one of trustedRootPath or tufRootURL
// must be non-nil and non-empty.
func GetCustomTrustedRoot(trustedRootPath, tufRootURL *string) (sigstoreRoot.TrustedMaterial, error) {
	if trustedRootPath != nil && *trustedRootPath != "" {
		return sigstoreRoot.NewTrustedRootFromPath(*trustedRootPath)
	}
	if tufRootURL != nil && *tufRootURL != "" {
		opts := sigstoreTUF.DefaultOptions().WithRepositoryBaseURL(*tufRootURL)
		return sigstoreRoot.NewLiveTrustedRoot(opts)
	}
	return nil, fmt.Errorf("either --trusted-root or --tuf-root-url must be provided")
}
