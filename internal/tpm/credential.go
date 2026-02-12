// Credential activation for TPM-based enrollment.
//
// Credential activation is the cryptographic proof that an AK lives inside
// the same TPM that owns a specific EK. The server encrypts a challenge
// using the EK public key, and only the real TPM can decrypt it.
//
// Flow:
// 1. Server calls TPM2_MakeCredential(EK_pub, AK_name, secret) -> credential blob
// 2. Client receives credential blob
// 3. Client calls TPM2_ActivateCredential(EK, AK, blob) -> decrypted secret
// 4. Client sends decrypted secret back to server
// 5. Server verifies it matches -> AK is proven to be in this TPM
//
// This is the anti-Sybil mechanism. Software cannot fake this.
//
// REQUIRES ELEVATION: ActivateCredential uses the EK, which requires
// admin/root access on most platforms.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │ SECURITY WARNING                                                    │
// │                                                                     │
// │ This file contains TPM operations that run as admin/root:           │
// │   - TPM2_CreatePrimary      (creates a transient EK, then flushed) │
// │   - TPM2_PolicySecret       (authorizes EK usage)                   │
// │   - TPM2_ActivateCredential (decrypts a server-provided blob)       │
// │                                                                     │
// │ ActivateCredential accepts a caller-provided credential blob and    │
// │ encrypted secret (base64 strings). These flow directly into TPM     │
// │ commands. The TPM itself validates them cryptographically, so       │
// │ malformed input causes a TPM error, not a security breach. However: │
// │                                                                     │
// │   1. The akHandle parameter selects which persistent key to use.    │
// │      Validate it is within our expected range (0x81000100-1FF).     │
// │   2. The credential blob comes from the SERVER, not the local user. │
// │      Ensure the SDK validates server identity (TLS + pinned cert)   │
// │      before passing blobs to this function.                         │
// │   3. Consider whether a malicious local process could abuse this    │
// │      to perform unwanted credential activations.                    │
// │                                                                     │
// │ As of Phase 1, ActivateCredential() is NOT called from main.go.    │
// │ The activate command returns NOT_IMPLEMENTED.                       │
// └─────────────────────────────────────────────────────────────────────┘
package tpm

import (
	"encoding/base64"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// ActivateCredentialResult holds the output of credential activation.
type ActivateCredentialResult struct {
	DecryptedCredential string `json:"decrypted_credential"` // Base64-encoded decrypted secret
}

// ActivateCredential decrypts a credential challenge from the server.
//
// This proves to the server that our AK is inside the TPM that owns
// the EK whose public key they used to encrypt the challenge.
//
// REQUIRES ELEVATION.
//
// Parameters:
//   - tpmTransport: open TPM connection
//   - akHandle: persistent handle of the AK (e.g., 0x81000100)
//   - credentialBlobB64: base64-encoded credential blob from the server
//   - encryptedSecretB64: base64-encoded encrypted secret from the server
//
// Returns the decrypted credential as base64.
func ActivateCredential(
	tpmTransport transport.TPMCloser,
	akHandle uint32,
	credentialBlobB64 string,
	encryptedSecretB64 string,
) (*ActivateCredentialResult, error) {
	// Decode the base64 inputs
	credentialBlob, err := base64.StdEncoding.DecodeString(credentialBlobB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in credential_blob: %w", err)
	}

	encryptedSecret, err := base64.StdEncoding.DecodeString(encryptedSecretB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in encrypted_secret: %w", err)
	}

	// Create a transient EK in the endorsement hierarchy using the standard
	// TCG EK Credential Profile RSA-2048 template.
	//
	// The template MUST exactly match what the TPM manufacturer used to create
	// the EK certificate. The TCG profile specifies this precisely:
	// - Type: RSA, NameAlg: SHA-256
	// - Attributes: fixedTPM | fixedParent | sensitiveDataOrigin |
	//               adminWithPolicy | restricted | decrypt
	// - AuthPolicy: PolicySecret(TPM_RH_ENDORSEMENT) = well-known SHA-256 digest
	// - Symmetric: AES-128-CFB
	// - Scheme: NULL, KeyBits: 2048, Exponent: 0 (= default 65537)
	// - Unique: 256 zero bytes (makes CreatePrimary deterministic for the same seed)
	tcgEKPolicyDigest := []byte{
		0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
		0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
		0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
		0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
	}

	ekTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			AdminWithPolicy:     true,
			Restricted:          true,
			Decrypt:             true,
		},
		AuthPolicy: tpm2.TPM2BDigest{Buffer: tcgEKPolicyDigest},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Symmetric: tpm2.TPMTSymDefObject{
					Algorithm: tpm2.TPMAlgAES,
					KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
					Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
				},
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgNull,
				},
				KeyBits: 2048,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgRSA,
			&tpm2.TPM2BPublicKeyRSA{Buffer: make([]byte, 256)},
		),
	}

	createEKCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(ekTemplate),
	}

	ekResp, err := createEKCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("could not load EK for credential activation: %w", err)
	}

	defer func() {
		flushCmd := tpm2.FlushContext{FlushHandle: ekResp.ObjectHandle}
		_, _ = flushCmd.Execute(tpmTransport)
	}()

	// Start a policy session for EK usage
	// The default EK requires PolicySecret(TPM_RH_ENDORSEMENT)
	sess, sessClose, err := tpm2.PolicySession(tpmTransport, tpm2.TPMAlgSHA256, 16)
	if err != nil {
		return nil, fmt.Errorf("could not start policy session: %w", err)
	}
	defer sessClose()

	// Execute PolicySecret with endorsement hierarchy auth
	policySecretCmd := tpm2.PolicySecret{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(nil),
		},
		PolicySession: sess.Handle(),
	}
	_, err = policySecretCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("PolicySecret(endorsement) failed: %w", err)
	}

	// Read the AK's TPM Name (required for ActivateCredential).
	// The go-tpm library needs the Name to bind the AK handle correctly.
	readAKPubCmd := tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(akHandle),
	}
	readAKPubResp, err := readAKPubCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("could not read AK public area at handle 0x%08X: %w", akHandle, err)
	}

	// Also read the EK's Name for its handle
	readEKPubCmd := tpm2.ReadPublic{
		ObjectHandle: ekResp.ObjectHandle,
	}
	readEKPubResp, err := readEKPubCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("could not read EK public area: %w", err)
	}

	// Call TPM2_ActivateCredential
	// ActivateHandle (AK) uses UserWithAuth, so PasswordAuth(nil) suffices.
	// KeyHandle (EK) uses the policy session (PolicySecret on endorsement).
	activateCmd := tpm2.ActivateCredential{
		ActivateHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(akHandle),
			Name:   readAKPubResp.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		KeyHandle: tpm2.AuthHandle{
			Handle: ekResp.ObjectHandle,
			Name:   readEKPubResp.Name,
			Auth:   sess,
		},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: credentialBlob},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encryptedSecret},
	}

	activateResp, err := activateCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("TPM2_ActivateCredential failed: %w", err)
	}

	decryptedSecret := base64.StdEncoding.EncodeToString(activateResp.CertInfo.Buffer)

	return &ActivateCredentialResult{
		DecryptedCredential: decryptedSecret,
	}, nil
}
