package custom

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	slsa1 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v1"

	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"github.com/slsa-framework/slsa-verifier/v2/options"
	"github.com/slsa-framework/slsa-verifier/v2/verifiers/utils"
)

// attestation is a generic in-toto SLSA v1.0 attestation statement.
type attestation struct {
	intoto.StatementHeader
	Predicate slsa1.ProvenancePredicate `json:"predicate"`
}

// verifyEnvAndCert verifies the provenance envelope contents against the
// expected options and returns the verified provenance and builder ID.
func verifyEnvAndCert(env *dsselib.Envelope,
	provenanceOpts *options.ProvenanceOpts,
	builderOpts *options.BuilderOpts,
) ([]byte, *utils.TrustedBuilderID, error) {
	customOpts := builderOpts.CustomOpts

	// Decode the provenance payload.
	payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding envelope payload: %w", err)
	}

	// Parse as SLSA v1.0 attestation.
	var att attestation
	if err := json.Unmarshal(payloadBytes, &att); err != nil {
		return nil, nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidDssePayload, err)
	}

	// Verify builder ID if provided.
	if builderOpts.ExpectedID != nil && *builderOpts.ExpectedID != "" {
		provBuilderID := att.Predicate.RunDetails.Builder.ID
		if provBuilderID != *builderOpts.ExpectedID {
			return nil, nil, fmt.Errorf("%w: expected %q, got %q",
				serrors.ErrorMismatchBuilderID, *builderOpts.ExpectedID, provBuilderID)
		}
	}

	// Verify build type if provided.
	if customOpts != nil && customOpts.BuildType != nil && *customOpts.BuildType != "" {
		provBuildType := att.Predicate.BuildDefinition.BuildType
		if provBuildType != *customOpts.BuildType {
			return nil, nil, fmt.Errorf("%w: expected %q, got %q",
				serrors.ErrorInvalidBuildType, *customOpts.BuildType, provBuildType)
		}
	}

	// Verify subject digest.
	if err := verifyDigest(att.Subject, provenanceOpts.ExpectedDigest); err != nil {
		return nil, nil, err
	}

	// Verify source URI.
	sourceURIPrefix := ""
	if customOpts != nil && customOpts.SourceURIPrefix != nil {
		sourceURIPrefix = *customOpts.SourceURIPrefix
	}
	if err := verifySourceURI(&att, provenanceOpts.ExpectedSourceURI, sourceURIPrefix); err != nil {
		return nil, nil, err
	}

	// Determine the builder ID to return.
	builderIDStr := att.Predicate.RunDetails.Builder.ID
	trustedBuilderID, err := utils.TrustedBuilderIDNew(builderIDStr, false)
	if err != nil {
		return nil, nil, err
	}

	fmt.Fprintf(os.Stderr, "Verified build using builder %q\n", builderIDStr)

	return payloadBytes, trustedBuilderID, nil
}

// verifySourceURI verifies the source URI from the provenance matches the
// expected source URI, optionally checking a prefix constraint.
func verifySourceURI(att *attestation, expectedSourceURI, sourceURIPrefix string) error {
	if expectedSourceURI == "" {
		return nil
	}

	source := utils.NormalizeGitURI(expectedSourceURI)

	// If a prefix is specified, check that the normalized source matches it.
	if sourceURIPrefix != "" {
		if !strings.HasPrefix(source, sourceURIPrefix) {
			return fmt.Errorf("%w: source URI %q does not match required prefix %q",
				serrors.ErrorMalformedURI, source, sourceURIPrefix)
		}
	}

	// Verify source from resolved dependencies.
	if len(att.Predicate.BuildDefinition.ResolvedDependencies) == 0 {
		return fmt.Errorf("%w: empty resolvedDependencies", serrors.ErrorInvalidDssePayload)
	}
	materialSourceURI := att.Predicate.BuildDefinition.ResolvedDependencies[0].URI
	if materialSourceURI == "" {
		return fmt.Errorf("%w: empty material source URI", serrors.ErrorMalformedURI)
	}

	materialBase, _, err := utils.ParseGitURIAndRef(materialSourceURI)
	if err != nil {
		return err
	}
	if materialBase != source {
		return fmt.Errorf("%w: expected source %q, got material source %q",
			serrors.ErrorMismatchSource, source, materialSourceURI)
	}

	return nil
}

// verifyDigest verifies the expected hash is present in the subject list.
func verifyDigest(subjects []intoto.Subject, expectedHash string) error {
	if expectedHash == "" {
		return nil
	}

	// 8 bits per hex char / 2 = 4 bits per hex char.
	bitLength := len(expectedHash) * 4
	expectedAlgo := fmt.Sprintf("sha%v", bitLength)
	if bitLength < 256 {
		return fmt.Errorf("%w: expected minimum 256-bit, got %d", serrors.ErrorInvalidHash, bitLength)
	}

	for _, subject := range subjects {
		hash, exists := subject.Digest[expectedAlgo]
		if !exists {
			continue
		}
		if hash == expectedHash {
			return nil
		}
	}

	return fmt.Errorf("expected hash '%s' not found: %w", expectedHash, serrors.ErrorMismatchHash)
}
