// TPM signing operations for challenge-response authentication.
//
// After enrollment, agents authenticate to 1id.com by signing a server-provided
// nonce with their AK (Attestation Identity Key). The AK private key never
// leaves the TPM chip, so this proves the agent is running on the same hardware
// that was enrolled.
//
// DOES NOT REQUIRE ELEVATION: The AK was created with UserWithAuth=true and
// empty auth, so TPM2_Sign works at normal user privilege. This is critical
// for ongoing authentication -- agents should not need UAC/sudo every time
// they sign in.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │ SECURITY NOTE                                                       │
// │                                                                     │
// │ The AK is a RESTRICTED signing key. The TPM enforces that it can    │
// │ only sign data that was NOT produced by the TPM itself (i.e., it    │
// │ will refuse to sign a TPM quote or audit digest). For signing       │
// │ arbitrary nonces, we must use a "ticket" from TPM2_Hash to prove    │
// │ the data originated outside the TPM, OR we use an unrestricted key. │
// │                                                                     │
// │ Since our AK IS restricted, we use TPM2_Hash to hash the nonce     │
// │ externally, then pass the hash + ticket to TPM2_Sign.               │
// └─────────────────────────────────────────────────────────────────────┘

package tpm

import (
	"encoding/base64"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// SignChallengeResult holds the output of signing a challenge nonce.
type SignChallengeResult struct {
	SignatureBase64 string `json:"signature_b64"`  // Base64-encoded raw RSA signature
	AKHandle        string `json:"ak_handle"`       // Handle used for signing
	Algorithm       string `json:"algorithm"`       // "RSASSA-SHA256"
}

// SignChallengeWithAK signs a nonce/challenge using the persistent AK.
//
// This is the core of hardware-backed authentication: the server sends a
// random nonce, we sign it with the AK (whose private key is locked inside
// the TPM), and the server verifies with the AK public key it stored at
// enrollment.
//
// DOES NOT REQUIRE ELEVATION on most platforms. The AK has UserWithAuth=true
// and empty password, so TPM2_Sign is accessible to any process that can
// open the TPM device.
//
// Parameters:
//   - tpmTransport: open TPM connection
//   - akHandle: persistent handle of the AK (e.g., 0x81000100)
//   - nonceBase64: base64-encoded nonce from the server
//
// Returns the RSA signature as base64.
func SignChallengeWithAK(
	tpmTransport transport.TPMCloser,
	akHandle uint32,
	nonceBase64 string,
) (*SignChallengeResult, error) {
	// Decode the nonce
	nonceBytes, err := base64.StdEncoding.DecodeString(nonceBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 nonce: %w", err)
	}

	if len(nonceBytes) == 0 || len(nonceBytes) > 1024 {
		return nil, fmt.Errorf("nonce must be 1-1024 bytes, got %d", len(nonceBytes))
	}

	// The AK is a RESTRICTED signing key. The TPM will refuse to sign data
	// unless we prove it wasn't produced by the TPM itself. We use TPM2_Hash
	// to hash the nonce on the TPM, which returns a "ticket" proving the data
	// came from outside.
	hashCmd := tpm2.Hash{
		Data:      tpm2.TPM2BMaxBuffer{Buffer: nonceBytes},
		HashAlg:   tpm2.TPMAlgSHA256,
		Hierarchy: tpm2.TPMRHEndorsement,
	}

	hashResp, err := hashCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Hash failed: %w", err)
	}

	// Read the AK's public area to get its TPM Name.
	// go-tpm requires the Name for authorization checks.
	readPubResp, err := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(akHandle),
	}.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("could not read AK public area (handle 0x%08X): %w", akHandle, err)
	}

	// Now sign the hash using the AK.
	// The ticket from TPM2_Hash proves the data originated externally,
	// which satisfies the restricted key requirement.
	signCmd := tpm2.Sign{
		KeyHandle: tpm2.NamedHandle{
			Handle: tpm2.TPMHandle(akHandle),
			Name:   readPubResp.Name,
		},
		Digest: hashResp.OutHash,
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{HashAlg: tpm2.TPMAlgSHA256},
			),
		},
		Validation: hashResp.Validation,
	}

	signResp, err := signCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("TPM2_Sign failed: %w", err)
	}

	// Extract the raw RSA signature bytes
	rsaSig, err := signResp.Signature.Signature.RSASSA()
	if err != nil {
		return nil, fmt.Errorf("could not extract RSASSA signature: %w", err)
	}

	signatureB64 := base64.StdEncoding.EncodeToString(rsaSig.Sig.Buffer)

	return &SignChallengeResult{
		SignatureBase64: signatureB64,
		AKHandle:        fmt.Sprintf("0x%08X", akHandle),
		Algorithm:       "RSASSA-SHA256",
	}, nil
}
