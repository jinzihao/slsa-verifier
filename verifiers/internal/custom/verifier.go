package custom

import (
	"context"
	"fmt"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/register"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

const VerifierName = "CUSTOM"

//nolint:gochecknoinits
func init() {
	register.RegisterVerifier(VerifierName, &CustomVerifier{})
}

// CustomVerifier verifies provenance from non-GitHub build systems
// that use their own Sigstore infrastructure (Fulcio, Rekor, CT log).
type CustomVerifier struct{}

// IsAuthoritativeFor returns false because the custom verifier is never selected
// through the builder ID dispatch loop. It is only selected explicitly when
// custom CLI flags (--oidc-issuer) are provided, via the getVerifier() logic.
func (v *CustomVerifier) IsAuthoritativeFor(_ string) bool {
	return false
}

// VerifyArtifact verifies provenance for an artifact using custom trust configuration.
func (v *CustomVerifier) VerifyArtifact(ctx context.Context,
	provenance []byte, artifactHash string,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, *utils.TrustedBuilderID, error) {
	customOpts := builderOpts.CustomOpts
	if customOpts == nil || customOpts.OidcIssuer == nil {
		return nil, nil, fmt.Errorf("%w: custom verifier requires --oidc-issuer", serrors.ErrorInvalidOIDCIssuer)
	}

	// Only Sigstore bundle format is supported.
	if !isSigstoreBundle(provenance) {
		return nil, nil, fmt.Errorf("custom verifier only supports Sigstore bundle format provenance")
	}

	// Load custom trusted root.
	trustedMaterial, err := utils.GetCustomTrustedRoot(customOpts.TrustedRootPath, customOpts.TufRootURL)
	if err != nil {
		return nil, nil, fmt.Errorf("loading custom trusted root: %w", err)
	}

	// Determine certificate identity regexp.
	certIdentityRegexp := ".*"
	if customOpts.CertificateIdentityRegexp != nil && *customOpts.CertificateIdentityRegexp != "" {
		certIdentityRegexp = *customOpts.CertificateIdentityRegexp
	}

	// Verify the bundle: rekor entry, certificate chain, SCTs, identity, DSSE signature.
	signedAtt, err := verifyProvenanceBundle(ctx, provenance, trustedMaterial,
		*customOpts.OidcIssuer, certIdentityRegexp)
	if err != nil {
		return nil, nil, err
	}

	// Verify provenance contents: builder ID, build type, source URI, digest.
	return verifyEnvAndCert(signedAtt.Envelope, provenanceOpts, builderOpts)
}

// VerifyImage is not supported by the custom verifier.
func (v *CustomVerifier) VerifyImage(_ context.Context,
	_ []byte, _ string,
	_ *options.ProvenanceOpts,
	_ *options.BuilderOpts,
) ([]byte, *utils.TrustedBuilderID, error) {
	return nil, nil, fmt.Errorf("%w: custom verifier does not support image verification", serrors.ErrorNotSupported)
}

// VerifyGithubAttestation is not supported by the custom verifier.
func (v *CustomVerifier) VerifyGithubAttestation(_ context.Context,
	_ []byte,
	_ *options.ProvenanceOpts,
	_ *options.BuilderOpts,
) ([]byte, *utils.TrustedBuilderID, error) {
	return nil, nil, fmt.Errorf("%w: custom verifier does not support GitHub attestation verification", serrors.ErrorNotSupported)
}

// VerifyNpmPackage is not supported by the custom verifier.
func (v *CustomVerifier) VerifyNpmPackage(_ context.Context,
	_ []byte, _ string,
	_ *options.ProvenanceOpts,
	_ *options.BuilderOpts,
) ([]byte, *utils.TrustedBuilderID, error) {
	return nil, nil, fmt.Errorf("%w: custom verifier does not support npm package verification", serrors.ErrorNotSupported)
}
