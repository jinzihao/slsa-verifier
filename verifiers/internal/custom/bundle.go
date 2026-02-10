package custom

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	cjson "github.com/docker/go/canonical/json"
	goapiruntime "github.com/go-openapi/runtime"
	dsselib "github.com/secure-systems-lab/go-securesystemslib/dsse"
	bundle_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	proto_v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	rekorClient "github.com/sigstore/rekor/pkg/client"
	rekorGenClient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/dsse"
	dsse_v001 "github.com/sigstore/rekor/pkg/types/dsse/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/intoto"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	rverify "github.com/sigstore/rekor/pkg/verify"
	sigstoreFulcioCertificate "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	sigstoreRoot "github.com/sigstore/sigstore-go/pkg/root"
	sigstoreVerify "github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	dsseverifier "github.com/sigstore/sigstore/pkg/signature/dsse"
	"github.com/slsa-framework/slsa-github-generator/signing/envelope"
	serrors "github.com/slsa-framework/slsa-verifier/v2/errors"
	"google.golang.org/protobuf/encoding/protojson"

	"sigs.k8s.io/release-utils/version"
)

// signedAttestation contains a signed DSSE envelope
// and its associated signing certificate.
type signedAttestation struct {
	Envelope   *dsselib.Envelope
	SigningCert *x509.Certificate
	RekorEntry *models.LogEntryAnon
	PublicKey  *proto_v1.PublicKeyIdentifier
}

// verifyProvenanceBundle verifies the DSSE envelope using the offline Rekor bundle
// with the given trusted material and certificate identity parameters.
func verifyProvenanceBundle(ctx context.Context, bundleBytes []byte,
	trustedMaterial sigstoreRoot.TrustedMaterial,
	oidcIssuer, certIdentityRegexp string,
) (*signedAttestation, error) {
	proposedSignedAtt, err := verifyBundleAndEntryFromBytes(ctx, bundleBytes, trustedMaterial)
	if err != nil {
		return nil, err
	}
	if err := verifySignedAttestation(proposedSignedAtt, trustedMaterial, oidcIssuer, certIdentityRegexp); err != nil {
		return nil, err
	}
	return proposedSignedAtt, nil
}

// verifyBundleAndEntryFromBytes validates the rekor entry in the bundle
// and that the entry (cert, signatures) matches the data in the bundle.
func verifyBundleAndEntryFromBytes(ctx context.Context, bundleBytes []byte,
	trustedMaterial sigstoreRoot.TrustedMaterial,
) (*signedAttestation, error) {
	var bundle bundle_v1.Bundle
	if err := protojson.Unmarshal(bundleBytes, &bundle); err != nil {
		return nil, fmt.Errorf("unmarshaling bundle: %w", err)
	}
	return verifyBundleAndEntry(ctx, &bundle, trustedMaterial)
}

// verifyBundleAndEntry validates the rekor entry in the bundle
// and that the entry (cert, signatures) matches the data in the bundle.
func verifyBundleAndEntry(ctx context.Context, bundle *bundle_v1.Bundle,
	trustedMaterial sigstoreRoot.TrustedMaterial,
) (*signedAttestation, error) {
	if bundle.GetVerificationMaterial() == nil ||
		len(bundle.GetVerificationMaterial().GetTlogEntries()) == 0 {
		return nil, fmt.Errorf("bundle missing offline tlog verification material %d",
			len(bundle.GetVerificationMaterial().GetTlogEntries()))
	}

	// Verify tlog entry.
	tlogEntry := bundle.GetVerificationMaterial().GetTlogEntries()[0]
	rekorEntry, err := verifyRekorEntryFromBundle(ctx, tlogEntry, trustedMaterial)
	if err != nil {
		return nil, err
	}

	// Extract the PublicKey.
	publicKey := bundle.GetVerificationMaterial().GetPublicKey()

	// Extract DSSE envelope.
	env, err := getEnvelopeFromBundle(bundle)
	if err != nil {
		return nil, err
	}

	// Match tlog entry signature with the envelope.
	if err := matchRekorEntryWithEnvelope(tlogEntry, env); err != nil {
		return nil, fmt.Errorf("matching bundle entry with content: %w", err)
	}

	// Get certificate from bundle.
	cert, err := getLeafCertFromBundle(bundle)
	if err != nil {
		return nil, err
	}

	return &signedAttestation{
		SigningCert: cert,
		PublicKey:   publicKey,
		Envelope:    env,
		RekorEntry:  rekorEntry,
	}, nil
}

// verifyRekorEntryFromBundle extracts and verifies the Rekor entry from the Sigstore
// bundle verification material, validating the SignedEntryTimestamp.
func verifyRekorEntryFromBundle(ctx context.Context, tlogEntry *v1.TransparencyLogEntry,
	trustedMaterial sigstoreRoot.TrustedMaterial,
) (*models.LogEntryAnon, error) {
	canonicalBody := tlogEntry.GetCanonicalizedBody()
	logID := hex.EncodeToString(tlogEntry.GetLogId().GetKeyId())
	rekorEntry := &models.LogEntryAnon{
		Body:           canonicalBody,
		IntegratedTime: &tlogEntry.IntegratedTime,
		LogIndex:       &tlogEntry.LogIndex,
		LogID:          &logID,
		Verification: &models.LogEntryAnonVerification{
			SignedEntryTimestamp: tlogEntry.GetInclusionPromise().GetSignedEntryTimestamp(),
		},
	}

	if _, err := verifyTlogEntry(ctx, *rekorEntry, false, trustedMaterial); err != nil {
		return nil, err
	}

	return rekorEntry, nil
}

// verifyTlogEntry verifies a Rekor entry content against a trusted Rekor key.
func verifyTlogEntry(ctx context.Context, e models.LogEntryAnon,
	verifyInclusion bool, trustedMaterial sigstoreRoot.TrustedMaterial,
) (*models.LogEntryAnon, error) {
	rekorLogsMap := trustedMaterial.RekorLogs()
	keyID := *e.LogID
	rekorLog, ok := rekorLogsMap[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorPubKey, "Rekor log ID not found in trusted root")
	}
	pubKey, ok := rekorLog.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorPubKey, "rekor public key is not an ECDSA key")
	}

	verifier, err := signature.LoadECDSAVerifier(pubKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorPubKey, err)
	}

	if verifyInclusion {
		err = rverify.VerifyLogEntry(ctx, &e, verifier)
	} else {
		err = rverify.VerifySignedEntryTimestamp(ctx, &e, verifier)
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorInvalidRekorEntry, err)
	}

	return &e, nil
}

// verifySignedAttestation verifies the certificate chain, SCTs, identity, and
// DSSE signature using the given trusted material and identity parameters.
func verifySignedAttestation(signedAtt *signedAttestation,
	trustedMaterial sigstoreRoot.TrustedMaterial,
	oidcIssuer, certIdentityRegexp string,
) error {
	cert := signedAtt.SigningCert
	attBytes, err := cjson.MarshalCanonical(signedAtt.Envelope)
	if err != nil {
		return err
	}
	signatureTimestamp := time.Unix(*signedAtt.RekorEntry.IntegratedTime, 0)

	// Verify the certificate chain, and that the certificate was valid at the time of signing.
	if err := sigstoreVerify.VerifyLeafCertificate(signatureTimestamp, cert, trustedMaterial); err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidCertificate, err)
	}

	// Verify the Signed Certificate Timestamps (SCTs).
	if err := sigstoreVerify.VerifySignedCertificateTimestamp(cert, 1, trustedMaterial); err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidCertificate, err)
	}

	// Verify the certificate identity information.
	summary, err := sigstoreFulcioCertificate.SummarizeCertificate(cert)
	if err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidCertificate, err)
	}
	certID, err := sigstoreVerify.NewShortCertificateIdentity(oidcIssuer, "", "", certIdentityRegexp)
	if err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidCertificate, err)
	}
	if err := certID.Verify(summary); err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidCertificate, err)
	}

	// Verify signature using validated certificate.
	v, err := signature.LoadVerifier(cert.PublicKey, crypto.SHA256)
	if err != nil {
		return err
	}
	v = dsseverifier.WrapVerifier(v)
	if err := v.VerifySignature(bytes.NewReader(attBytes), bytes.NewReader(attBytes)); err != nil {
		return fmt.Errorf("%w: %s", serrors.ErrorInvalidSignature, err)
	}
	return nil
}

// --- Bundle helper functions adapted from gha/bundle.go ---

// getEnvelopeFromBundle extracts the DSSE envelope from the Sigstore bundle.
func getEnvelopeFromBundle(bundle *bundle_v1.Bundle) (*dsselib.Envelope, error) {
	dsseEnvelope := bundle.GetDsseEnvelope()
	if dsseEnvelope == nil {
		return nil, errors.New("expected DSSE bundle content")
	}
	env := &dsselib.Envelope{
		PayloadType: dsseEnvelope.GetPayloadType(),
		Payload:     base64.StdEncoding.EncodeToString(dsseEnvelope.GetPayload()),
	}
	for _, sig := range dsseEnvelope.GetSignatures() {
		env.Signatures = append(env.Signatures, dsselib.Signature{
			KeyID: sig.GetKeyid(),
			Sig:   base64.StdEncoding.EncodeToString(sig.GetSig()),
		})
	}
	return env, nil
}

// getLeafCertFromBundle extracts the signing cert from the Sigstore bundle.
func getLeafCertFromBundle(bundle *bundle_v1.Bundle) (*x509.Certificate, error) {
	// First try the newer method.
	if bundleCert := bundle.GetVerificationMaterial().GetCertificate(); bundleCert != nil {
		certBytes := bundleCert.GetRawBytes()
		return x509.ParseCertificate(certBytes)
	}
	// Otherwise, try the original method.
	certChain := bundle.GetVerificationMaterial().GetX509CertificateChain().GetCertificates()
	if len(certChain) == 0 {
		return nil, errors.New("missing signing certificate in bundle")
	}
	certBytes := certChain[0].GetRawBytes()
	return x509.ParseCertificate(certBytes)
}

// matchRekorEntryWithEnvelope ensures that the log entry references the given DSSE envelope.
func matchRekorEntryWithEnvelope(tlogEntry *v1.TransparencyLogEntry, env *dsselib.Envelope) error {
	if len(env.Signatures) == 0 {
		return errors.New("envelope has no signatures")
	}

	kindVersion := tlogEntry.GetKindVersion()

	if kindVersion.Kind == "intoto" && kindVersion.Version == "0.0.2" {
		return matchRekorEntryWithEnvelopeIntotov002(tlogEntry, env)
	}
	if kindVersion.Kind == "dsse" && kindVersion.Version == "0.0.1" {
		return matchRekorEntryWithEnvelopeDSSEv001(tlogEntry, env)
	}

	return fmt.Errorf("unsupported tlog entry type: wanted either intoto v0.0.2 or dsse v0.0.1, got: %s %s",
		kindVersion.Kind, kindVersion.Version)
}

func matchRekorEntryWithEnvelopeIntotov002(tlogEntry *v1.TransparencyLogEntry, env *dsselib.Envelope) error {
	canonicalBody := tlogEntry.GetCanonicalizedBody()
	var toto models.Intoto
	var intotoObj models.IntotoV002Schema
	if err := json.Unmarshal(canonicalBody, &toto); err != nil {
		return fmt.Errorf("parsing tlog entry body: %w", err)
	}
	specMarshal, err := json.Marshal(toto.Spec)
	if err != nil {
		return fmt.Errorf("parsing tlog entry body: %w", err)
	}
	if err := json.Unmarshal(specMarshal, &intotoObj); err != nil {
		return fmt.Errorf("parsing tlog entry body: %w", err)
	}

	if len(env.Signatures) != len(intotoObj.Content.Envelope.Signatures) {
		return fmt.Errorf("bundle tlog entry and envelope have an unequal number of signatures: wanted %d, got %d",
			len(env.Signatures), len(intotoObj.Content.Envelope.Signatures))
	}

	for _, sig := range env.Signatures {
		encodedEnvSig := base64.StdEncoding.EncodeToString([]byte(sig.Sig))
		if !slices.ContainsFunc(
			intotoObj.Content.Envelope.Signatures,
			func(canonicalSig *models.IntotoV002SchemaContentEnvelopeSignaturesItems0) bool {
				return canonicalSig.Sig.String() == encodedEnvSig
			},
		) {
			return errors.New("bundle tlog entry does not match signature")
		}
	}
	return nil
}

func matchRekorEntryWithEnvelopeDSSEv001(tlogEntry *v1.TransparencyLogEntry, env *dsselib.Envelope) error {
	canonicalBody := tlogEntry.GetCanonicalizedBody()
	var dsseObj models.DSSE
	if err := json.Unmarshal(canonicalBody, &dsseObj); err != nil {
		return fmt.Errorf("parsing tlog entry body: %w", err)
	}
	var dsseSchemaObj models.DSSEV001Schema
	specMarshal, err := json.Marshal(dsseObj.Spec)
	if err != nil {
		return fmt.Errorf("parsing tlog entry body: %w", err)
	}
	if err := json.Unmarshal(specMarshal, &dsseSchemaObj); err != nil {
		return fmt.Errorf("parsing tlog entry body: %w", err)
	}

	if len(env.Signatures) != len(dsseSchemaObj.Signatures) {
		return fmt.Errorf("bundle tlog entry and envelope have an unequal number of signatures: wanted %d, got %d",
			len(env.Signatures), len(dsseSchemaObj.Signatures))
	}
	for _, sig := range env.Signatures {
		if !slices.ContainsFunc(
			dsseSchemaObj.Signatures,
			func(canonicalSig *models.DSSEV001SchemaSignaturesItems0) bool {
				return *canonicalSig.Signature == sig.Sig
			},
		) {
			return errors.New("bundle tlog entry does not match signature")
		}
	}
	return nil
}

// isSigstoreBundle checks if the provenance is a Sigstore bundle.
func isSigstoreBundle(b []byte) bool {
	var bundle bundle_v1.Bundle
	if err := protojson.Unmarshal(b, &bundle); err != nil {
		return false
	}
	return true
}

// --- Non-bundle verification path (legacy DSSE envelope with Rekor search) ---

// getRekorClient creates a Rekor client using the base URL from the trusted
// material's Rekor log entries. Falls back to the default public Rekor if
// no log entries are found.
func getRekorClient(trustedMaterial sigstoreRoot.TrustedMaterial) (*rekorGenClient.Rekor, error) {
	rekorAddr := "https://rekor.sigstore.dev"
	rekorLogs := trustedMaterial.RekorLogs()
	for _, log := range rekorLogs {
		if log.BaseURL != "" {
			rekorAddr = log.BaseURL
			break
		}
	}
	userAgent := fmt.Sprintf("slsa-verifier/%s (%s; %s)", version.GetVersionInfo().GitVersion, runtime.GOOS, runtime.GOARCH)
	return rekorClient.GetRekorClient(rekorAddr, rekorClient.WithUserAgent(userAgent))
}

// verifyProvenanceSignature verifies the DSSE envelope using online Rekor
// search, for non-bundle provenance format.
func verifyProvenanceSignature(ctx context.Context,
	trustedMaterial sigstoreRoot.TrustedMaterial,
	rClient *rekorGenClient.Rekor,
	provenance []byte, artifactHash string,
	oidcIssuer, certIdentityRegexp string,
) (*signedAttestation, error) {
	if hasCertInEnvelope(provenance) {
		return getValidSignedAttestationWithCert(ctx, rClient, provenance,
			trustedMaterial, oidcIssuer, certIdentityRegexp)
	}

	fmt.Fprintf(os.Stderr, "No certificate provided, trying Redis search index to find entries by subject digest\n")
	return searchValidSignedAttestation(ctx, artifactHash, provenance,
		rClient, trustedMaterial, oidcIssuer, certIdentityRegexp)
}

// hasCertInEnvelope checks if a valid x509 certificate is present in the envelope.
func hasCertInEnvelope(provenance []byte) bool {
	certPem, err := envelope.GetCertFromEnvelope(provenance)
	return err == nil && len(certPem) > 0
}

// getValidSignedAttestationWithCert finds and validates matching Rekor entry UUIDs
// using the certificate embedded in the DSSE envelope.
func getValidSignedAttestationWithCert(ctx context.Context,
	rClient *rekorGenClient.Rekor,
	provenance []byte,
	trustedMaterial sigstoreRoot.TrustedMaterial,
	oidcIssuer, certIdentityRegexp string,
) (*signedAttestation, error) {
	params := entries.NewSearchLogQueryParams()
	searchLogQuery := models.SearchLogQuery{}
	certPem, err := envelope.GetCertFromEnvelope(provenance)
	if err != nil {
		return nil, fmt.Errorf("error getting certificate from provenance: %w", err)
	}

	intotoEntry, err := newIntotoEntry(certPem, provenance)
	if err != nil {
		return nil, fmt.Errorf("error creating intoto entry: %w", err)
	}
	dsseEntry, err := newDsseEntry(certPem, provenance)
	if err != nil {
		return nil, err
	}
	searchLogQuery.SetEntries([]models.ProposedEntry{intotoEntry, dsseEntry})

	params.SetEntry(&searchLogQuery)
	resp, err := rClient.Entries.SearchLogQuery(params)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorSearch, err.Error())
	}

	if len(resp.GetPayload()) != 1 {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorSearch, "no matching rekor entries")
	}

	logEntry := resp.Payload[0]
	var rekorEntry models.LogEntryAnon
	for uuid, e := range logEntry {
		if _, err := verifyTlogEntry(ctx, e, true, trustedMaterial); err != nil {
			return nil, fmt.Errorf("error verifying tlog entry: %w", err)
		}
		rekorEntry = e
		fmt.Fprintf(os.Stderr, "Verified signature against tlog entry index %d at UUID: %s\n", *e.LogIndex, uuid)
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(certPem)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("error unmarshaling certificate from pem")
	}

	env, err := envelopeFromBytes(provenance)
	if err != nil {
		return nil, err
	}

	proposedSignedAtt := &signedAttestation{
		SigningCert: certs[0],
		Envelope:    env,
		RekorEntry:  &rekorEntry,
	}

	if err := verifySignedAttestation(proposedSignedAtt, trustedMaterial, oidcIssuer, certIdentityRegexp); err != nil {
		return nil, err
	}

	return proposedSignedAtt, nil
}

// searchValidSignedAttestation searches for a valid signing certificate using
// the Rekor search index by artifact digest.
func searchValidSignedAttestation(ctx context.Context,
	artifactHash string, provenance []byte,
	rClient *rekorGenClient.Rekor,
	trustedMaterial sigstoreRoot.TrustedMaterial,
	oidcIssuer, certIdentityRegexp string,
) (*signedAttestation, error) {
	uuids, err := getUUIDsByArtifactDigest(rClient, artifactHash)
	if err != nil {
		return nil, err
	}

	env, err := envelopeFromBytes(provenance)
	if err != nil {
		return nil, err
	}

	var errs []string
	for _, uuid := range uuids {
		entry, err := verifyTlogEntryByUUID(ctx, rClient, uuid, trustedMaterial)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: verifying tlog entry %s", err, uuid))
			continue
		}

		cert, err := extractCert(entry)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: extracting certificate from %s", err, uuid))
			continue
		}

		proposedSignedAtt := &signedAttestation{
			Envelope:   env,
			SigningCert: cert,
			RekorEntry: entry,
		}

		err = verifySignedAttestation(proposedSignedAtt, trustedMaterial, oidcIssuer, certIdentityRegexp)
		if errors.Is(err, serrors.ErrorInternal) {
			return nil, err
		} else if err != nil {
			errs = append(errs, err.Error())
			continue
		}

		fmt.Fprintf(os.Stderr, "Verified signature against tlog entry index %d at UUID: %s\n", *entry.LogIndex, uuid)
		return proposedSignedAtt, nil
	}

	return nil, fmt.Errorf("%w: got unexpected errors %s", serrors.ErrorNoValidRekorEntries, strings.Join(errs, ", "))
}

// verifyTlogEntryByUUID fetches and verifies a single Rekor tlog entry by UUID.
func verifyTlogEntryByUUID(ctx context.Context, client *rekorGenClient.Rekor,
	entryUUID string, trustedMaterial sigstoreRoot.TrustedMaterial,
) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	params.EntryUUID = entryUUID

	lep, err := client.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}

	if len(lep.Payload) != 1 {
		return nil, errors.New("UUID value can not be extracted")
	}

	uuid, err := sharding.GetUUIDFromIDString(params.EntryUUID)
	if err != nil {
		return nil, err
	}

	for k, entry := range lep.Payload {
		returnUUID, err := sharding.GetUUIDFromIDString(k)
		if err != nil {
			return nil, err
		}
		if returnUUID != uuid {
			return nil, errors.New("expected matching UUID")
		}
		return verifyTlogEntry(ctx, entry, true, trustedMaterial)
	}

	return nil, serrors.ErrorRekorSearch
}

// getUUIDsByArtifactDigest finds all entry UUIDs by the digest of the artifact binary.
func getUUIDsByArtifactDigest(rClient *rekorGenClient.Rekor, artifactHash string) ([]string, error) {
	params := index.NewSearchIndexParams()
	params.Query = &models.SearchIndex{Hash: fmt.Sprintf("sha256:%v", artifactHash)}
	resp, err := rClient.Index.SearchIndex(params)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", serrors.ErrorRekorSearch, err.Error())
	}

	if len(resp.Payload) == 0 {
		return nil, fmt.Errorf("%w: no matching entries found", serrors.ErrorRekorSearch)
	}

	return resp.GetPayload(), nil
}

// extractCert extracts the signing certificate from a Rekor log entry.
func extractCert(e *models.LogEntryAnon) (*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), goapiruntime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *intoto_v001.V001Entry:
		publicKeyB64, err = e.IntotoObj.PublicKey.MarshalText()
	case *dsse_v001.V001Entry:
		if len(e.DSSEObj.Signatures) > 1 {
			return nil, errors.New("multiple signatures on DSSE envelopes are not currently supported")
		}
		publicKeyB64, err = e.DSSEObj.Signatures[0].Verifier.MarshalText()
	default:
		return nil, errors.New("unexpected tlog entry type")
	}
	if err != nil {
		return nil, err
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) != 1 {
		return nil, errors.New("unexpected number of cert pem tlog entry")
	}

	return certs[0], err
}

// newIntotoEntry creates a ProposedEntry for intoto format.
func newIntotoEntry(certPem, provenance []byte) (models.ProposedEntry, error) {
	if len(certPem) == 0 {
		return nil, fmt.Errorf("no signing certificate found in intoto envelope")
	}
	return types.NewProposedEntry(context.Background(), intoto.KIND, intoto_v001.APIVERSION, types.ArtifactProperties{
		ArtifactBytes:  provenance,
		PublicKeyBytes: [][]byte{certPem},
	})
}

// newDsseEntry creates a ProposedEntry for dsse format.
func newDsseEntry(certPem, provenance []byte) (models.ProposedEntry, error) {
	if len(certPem) == 0 {
		return nil, fmt.Errorf("no signing certificate found in intoto envelope")
	}
	return types.NewProposedEntry(context.Background(), dsse.KIND, dsse_v001.APIVERSION, types.ArtifactProperties{
		ArtifactBytes:  provenance,
		PublicKeyBytes: [][]byte{certPem},
	})
}

// envelopeFromBytes reads a DSSE envelope from the given payload.
func envelopeFromBytes(payload []byte) (*dsselib.Envelope, error) {
	env := &dsselib.Envelope{}
	err := json.Unmarshal(payload, env)
	return env, err
}
