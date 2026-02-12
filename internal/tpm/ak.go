// AK (Attestation Identity Key) generation and management.
//
// The AK is the "working key" that the agent uses daily. Unlike the EK
// (which is burned in at manufacture and should rarely be used directly),
// the AK is created by the agent during enrollment and persisted in the
// TPM's persistent storage.
//
// The AK is cryptographically bound to the EK via credential activation.
// This binding proves that the AK lives inside the same TPM that owns the EK.
//
// REQUIRES ELEVATION: Creating and persisting keys in the TPM requires
// admin/root privileges.
//
// ┌─────────────────────────────────────────────────────────────────────┐
// │ SECURITY WARNING                                                    │
// │                                                                     │
// │ This file contains TPM WRITE operations:                            │
// │   - TPM2_CreatePrimary  (creates a key in the TPM)                  │
// │   - TPM2_EvictControl   (persists a key to a permanent handle)      │
// │                                                                     │
// │ This binary runs as admin/root. Any function in this file that is   │
// │ reachable from main.go is callable by ANY local process that can    │
// │ spawn our binary. Before wiring GenerateAK() into a CLI command:    │
// │                                                                     │
// │   1. Validate ALL inputs (handle ranges, key parameters)            │
// │   2. Consider rate-limiting (TPM persistent storage is finite)      │
// │   3. Consider whether the operation should require user consent     │
// │      (e.g., a second UAC prompt or confirmation dialog)             │
// │   4. Ensure no caller-controlled data flows into TPM commands       │
// │   5. Audit the full call chain from main() to the TPM command       │
// │                                                                     │
// │ As of Phase 1, GenerateAK() is NOT called from main.go.            │
// └─────────────────────────────────────────────────────────────────────┘
package tpm

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// AKData holds information about a generated Attestation Identity Key.
type AKData struct {
	PublicKeyPEM       string `json:"ak_public_pem"`       // PEM-encoded public key (standard PKIX format)
	Handle             string `json:"ak_handle"`           // Persistent handle (hex string, e.g., "0x81000100")
	HandleNumeric      uint32 `json:"-"`                   // Persistent handle as uint32 (internal use)
	KeyAlgorithm       string `json:"ak_algorithm"`        // "rsa-2048" or "ecc-p256"
	TPMTPublicBytes    []byte `json:"tpmt_public_bytes"`   // Raw marshaled TPMT_PUBLIC (for computing TPM Name)
	TPMName            string `json:"ak_tpm_name"`         // Hex-encoded TPM Name (SHA256 nameAlg: 000b || sha256(tpmt_public))
	CreationTicket     []byte `json:"creation_ticket,omitempty"`
}

// Persistent handle range for 1id AKs.
// We use 0x81000100-0x810001FF to avoid conflicts with other software.
const (
	persistentAKHandleStart = 0x81000100
	persistentAKHandleEnd   = 0x810001FF
)

// GetOrCreateAK returns an existing persistent AK from our handle range,
// or creates and persists a new one if none exists.
//
// This is the safe entry point for enrollment: calling extract multiple
// times reuses the same AK rather than filling up persistent handle space.
//
// REQUIRES ELEVATION.
func GetOrCreateAK(tpmTransport transport.TPMCloser) (*AKData, error) {
	// Check if we already have a persistent AK in our range
	existingAK, err := readExistingPersistentAK(tpmTransport)
	if err == nil && existingAK != nil {
		return existingAK, nil
	}

	// No existing AK found -- generate a new one
	return generateAndPersistAK(tpmTransport)
}

// readExistingPersistentAK checks our AK handle range (0x81000100-0x810001FF)
// for an existing persistent AK by trying ReadPublic on each handle.
//
// This is more reliable than GetCapability enumeration, which can fail
// or return incomplete results on some TPM implementations.
//
// Returns nil, nil if no AK is found in our range.
func readExistingPersistentAK(tpmTransport transport.TPMCloser) (*AKData, error) {
	// Try each handle in our range directly with ReadPublic.
	// ReadPublic does NOT require auth -- it just reads the public area.
	// We only try the first 16 handles to keep it fast.
	maxProbe := uint32(persistentAKHandleStart + 16)
	if maxProbe > persistentAKHandleEnd {
		maxProbe = persistentAKHandleEnd
	}

	for handleVal := uint32(persistentAKHandleStart); handleVal <= maxProbe; handleVal++ {
		readPubCmd := tpm2.ReadPublic{
			ObjectHandle: tpm2.TPMHandle(handleVal),
		}
		readPubResp, err := readPubCmd.Execute(tpmTransport)
		if err != nil {
			// Handle not found at this index -- try next
			continue
		}

		// Found a persistent object -- check if it's an RSA signing key (our AK)
		akPublic, err := readPubResp.OutPublic.Contents()
		if err != nil {
			continue
		}

		// Verify this looks like our AK: RSA type, restricted, signing
		if akPublic.Type != tpm2.TPMAlgRSA {
			continue
		}
		if !akPublic.ObjectAttributes.Restricted || !akPublic.ObjectAttributes.SignEncrypt {
			continue
		}

		pubKeyPEM, err := marshalTPMPublicToPEM(akPublic)
		if err != nil {
			continue
		}

		tpmtPublicBytes := readPubResp.OutPublic.Bytes()
		akTPMNameBytes := readPubResp.Name.Buffer

		return &AKData{
			PublicKeyPEM:    string(pubKeyPEM),
			Handle:          fmt.Sprintf("0x%08X", handleVal),
			HandleNumeric:   handleVal,
			KeyAlgorithm:    "rsa-2048",
			TPMTPublicBytes: tpmtPublicBytes,
			TPMName:         hex.EncodeToString(akTPMNameBytes),
		}, nil
	}

	return nil, nil
}

// generateAndPersistAK creates a new Attestation Identity Key in the TPM
// and persists it to the first available handle in our range.
//
// The AK is an RSA-2048 restricted signing key, suitable for
// credential activation and challenge-response operations.
//
// REQUIRES ELEVATION.
//
// Returns the AK data including its public key and persistent handle.
func generateAndPersistAK(tpmTransport transport.TPMCloser) (*AKData, error) {
	// AK template: RSA-2048, restricted signing, SHA-256
	// This matches what go-attestation and most TPM enrollment tools use.
	akTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:             true,
			FixedParent:          true,
			SensitiveDataOrigin:  true,
			UserWithAuth:         true,
			Restricted:           true,
			SignEncrypt:           true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	}

	// Create the AK under the endorsement hierarchy.
	// The endorsement hierarchy requires explicit auth (empty password).
	createPrimaryCmd := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(akTemplate),
	}

	createResp, err := createPrimaryCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("TPM2_CreatePrimary for AK failed: %w", err)
	}

	// Extract the public key from the response
	akPublic, err := createResp.OutPublic.Contents()
	if err != nil {
		return nil, fmt.Errorf("could not read AK public area: %w", err)
	}

	pubKeyPEM, err := marshalTPMPublicToPEM(akPublic)
	if err != nil {
		return nil, fmt.Errorf("could not marshal AK public key: %w", err)
	}

	// Get the raw marshaled TPMT_PUBLIC bytes for computing the TPM Name.
	// The TPM Name = nameAlg (2 bytes) || Hash(TPMT_PUBLIC).
	// go-tpm returns this in OutPublic as TPM2B (size-prefixed), so we use
	// the Bytes() from the raw marshaled form.
	tpmtPublicBytes := createResp.OutPublic.Bytes()

	// The TPM Name is what the TPM computes internally.
	// go-tpm returns it in createResp.Name. We use that directly.
	akTPMNameBytes := createResp.Name.Buffer

	// Find an available persistent handle
	persistentHandle, err := findAvailablePersistentHandle(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("no available persistent handle for AK: %w", err)
	}

	// Make the AK persistent
	evictCmd := tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: createResp.ObjectHandle,
			Name:   createResp.Name,
		},
		PersistentHandle: tpm2.TPMHandle(persistentHandle),
	}

	_, err = evictCmd.Execute(tpmTransport)
	if err != nil {
		return nil, fmt.Errorf("TPM2_EvictControl (persist AK) failed: %w", err)
	}

	// Flush the transient object
	flushCmd := tpm2.FlushContext{FlushHandle: createResp.ObjectHandle}
	_, _ = flushCmd.Execute(tpmTransport)

	return &AKData{
		PublicKeyPEM:    string(pubKeyPEM),
		Handle:          fmt.Sprintf("0x%08X", persistentHandle),
		HandleNumeric:   persistentHandle,
		KeyAlgorithm:    "rsa-2048",
		TPMTPublicBytes: tpmtPublicBytes,
		TPMName:         hex.EncodeToString(akTPMNameBytes),
	}, nil
}

// marshalTPMPublicToPEM converts a TPM RSA public key structure to standard PKIX PEM.
//
// The TPM stores RSA public keys as just the modulus (N) bytes. The exponent
// is always 65537 (0x10001) per the TCG EK Credential Profile. We reconstruct
// a standard crypto/rsa.PublicKey and marshal it via x509.MarshalPKIXPublicKey.
func marshalTPMPublicToPEM(pub *tpm2.TPMTPublic) ([]byte, error) {
	rsaUnique, err := pub.Unique.RSA()
	if err != nil {
		return nil, fmt.Errorf("could not get RSA unique (modulus): %w", err)
	}

	// Build a standard crypto/rsa.PublicKey from the TPM modulus bytes.
	// TPM stores the modulus as unsigned big-endian bytes.
	n := new(big.Int).SetBytes(rsaUnique.Buffer)
	rsaPubKey := &rsa.PublicKey{
		N: n,
		E: 65537,
	}

	derBytes, err := x509.MarshalPKIXPublicKey(rsaPubKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal RSA public key to PKIX DER: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}), nil
}

// ComputeTPMNameFromPublicBytes computes the TPM Name from marshaled TPMT_PUBLIC bytes.
// TPM Name = nameAlg (2 bytes big-endian) || hash(TPMT_PUBLIC).
// For SHA-256 nameAlg: 0x000B || SHA256(bytes).
func ComputeTPMNameFromPublicBytes(tpmtPublicBytes []byte) []byte {
	digest := sha256.Sum256(tpmtPublicBytes)
	name := make([]byte, 2+sha256.Size)
	binary.BigEndian.PutUint16(name[0:2], uint16(tpm2.TPMAlgSHA256))
	copy(name[2:], digest[:])
	return name
}

// findAvailablePersistentHandle finds an unused persistent handle in our range.
func findAvailablePersistentHandle(tpmTransport transport.TPMCloser) (uint32, error) {
	// Query existing persistent handles
	getCapCmd := tpm2.GetCapability{
		Capability:    tpm2.TPMCapHandles,
		Property:      uint32(tpm2.TPMHTPersistent),
		PropertyCount: 256,
	}

	getCapResp, err := getCapCmd.Execute(tpmTransport)
	if err != nil {
		// If we can't enumerate, just try the first handle
		return persistentAKHandleStart, nil
	}

	handleList, err := getCapResp.CapabilityData.Data.Handles()
	if err != nil {
		return persistentAKHandleStart, nil
	}

	// Build a set of used handles
	usedHandles := make(map[uint32]bool)
	for _, h := range handleList.Handle {
		usedHandles[uint32(h)] = true
	}

	// Find the first available handle in our range
	for handle := uint32(persistentAKHandleStart); handle <= persistentAKHandleEnd; handle++ {
		if !usedHandles[handle] {
			return handle, nil
		}
	}

	return 0, fmt.Errorf("all persistent handles 0x%08X-0x%08X are in use", persistentAKHandleStart, persistentAKHandleEnd)
}
