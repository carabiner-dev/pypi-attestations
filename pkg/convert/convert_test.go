package convert

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/carabiner-dev/pypi-attestations/proto"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestUnmarshalAttestation(t *testing.T) {
	// Read the test data
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "pypi.attestation.json"))
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	// Unmarshal the attestation
	attestation, err := UnmarshalAttestation(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal attestation: %v", err)
	}

	// Validate basic fields
	if attestation.Version != 1 {
		t.Errorf("Expected version 1, got %d", attestation.Version)
	}

	if attestation.VerificationMaterial == nil {
		t.Fatal("VerificationMaterial is nil")
	}

	if len(attestation.VerificationMaterial.Certificate) == 0 {
		t.Error("Certificate is empty")
	}

	if len(attestation.VerificationMaterial.TransparencyEntries) == 0 {
		t.Error("No transparency entries")
	}

	if attestation.Envelope == nil {
		t.Fatal("Envelope is nil")
	}

	if len(attestation.Envelope.Statement) == 0 {
		t.Error("Statement is empty")
	}

	if len(attestation.Envelope.Signature) == 0 {
		t.Error("Signature is empty")
	}
}

func TestToBundle(t *testing.T) {
	// Read and unmarshal the test data
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "pypi.attestation.json"))
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	attestation, err := UnmarshalAttestation(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal attestation: %v", err)
	}

	// Convert to bundle
	bundle, err := ToBundle(attestation)
	if err != nil {
		t.Fatalf("Failed to convert to bundle: %v", err)
	}

	if bundle == nil || bundle.Bundle == nil {
		t.Fatal("Bundle is nil")
	}

	// Validate bundle structure
	if bundle.Bundle.VerificationMaterial == nil {
		t.Fatal("VerificationMaterial is nil")
	}

	if len(bundle.Bundle.VerificationMaterial.TlogEntries) == 0 {
		t.Error("No transparency log entries in bundle")
	}

	dsseEnvelope, ok := bundle.Bundle.Content.(*protobundle.Bundle_DsseEnvelope)
	if !ok {
		t.Fatal("Bundle does not contain a DSSE envelope")
	}

	if dsseEnvelope.DsseEnvelope == nil {
		t.Fatal("DSSE envelope is nil")
	}

	if len(dsseEnvelope.DsseEnvelope.Signatures) != 1 {
		t.Errorf("Expected 1 signature, got %d", len(dsseEnvelope.DsseEnvelope.Signatures))
	}
}

func TestFromBundle(t *testing.T) {
	// Read and unmarshal the test data
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "pypi.attestation.json"))
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	originalAttestation, err := UnmarshalAttestation(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal attestation: %v", err)
	}

	// Convert to bundle
	bundle, err := ToBundle(originalAttestation)
	if err != nil {
		t.Fatalf("Failed to convert to bundle: %v", err)
	}

	// Convert back to attestation
	attestation, err := FromBundle(bundle)
	if err != nil {
		t.Fatalf("Failed to convert from bundle: %v", err)
	}

	// Validate the attestation
	if attestation.Version != 1 {
		t.Errorf("Expected version 1, got %d", attestation.Version)
	}

	if attestation.VerificationMaterial == nil {
		t.Fatal("VerificationMaterial is nil")
	}

	if attestation.Envelope == nil {
		t.Fatal("Envelope is nil")
	}
}

func TestRoundTrip(t *testing.T) {
	// Read and unmarshal the test data
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "pypi.attestation.json"))
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	originalAttestation, err := UnmarshalAttestation(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal attestation: %v", err)
	}

	// Convert to bundle
	bundle, err := ToBundle(originalAttestation)
	if err != nil {
		t.Fatalf("Failed to convert to bundle: %v", err)
	}

	// Convert back to attestation
	roundTrippedAttestation, err := FromBundle(bundle)
	if err != nil {
		t.Fatalf("Failed to convert from bundle: %v", err)
	}

	// Compare the attestations
	if originalAttestation.Version != roundTrippedAttestation.Version {
		t.Errorf("Version mismatch: original=%d, round-tripped=%d",
			originalAttestation.Version, roundTrippedAttestation.Version)
	}

	// Compare certificates
	if !bytes.Equal(originalAttestation.VerificationMaterial.Certificate,
		roundTrippedAttestation.VerificationMaterial.Certificate) {
		t.Error("Certificate mismatch after round-trip")
	}

	// Compare envelope statement
	if !bytes.Equal(originalAttestation.Envelope.Statement,
		roundTrippedAttestation.Envelope.Statement) {
		t.Error("Statement mismatch after round-trip")
	}

	// Compare envelope signature
	if !bytes.Equal(originalAttestation.Envelope.Signature,
		roundTrippedAttestation.Envelope.Signature) {
		t.Error("Signature mismatch after round-trip")
	}

	// Compare transparency entries count
	if len(originalAttestation.VerificationMaterial.TransparencyEntries) !=
		len(roundTrippedAttestation.VerificationMaterial.TransparencyEntries) {
		t.Errorf("Transparency entries count mismatch: original=%d, round-tripped=%d",
			len(originalAttestation.VerificationMaterial.TransparencyEntries),
			len(roundTrippedAttestation.VerificationMaterial.TransparencyEntries))
	}

	// Compare transparency entries as JSON for easier comparison
	for i := range originalAttestation.VerificationMaterial.TransparencyEntries {
		orig := originalAttestation.VerificationMaterial.TransparencyEntries[i]
		roundTripped := roundTrippedAttestation.VerificationMaterial.TransparencyEntries[i]

		origJSON, err := protojson.Marshal(orig)
		if err != nil {
			t.Fatalf("Failed to marshal original transparency entry %d: %v", i, err)
		}

		rtJSON, err := protojson.Marshal(roundTripped)
		if err != nil {
			t.Fatalf("Failed to marshal round-tripped transparency entry %d: %v", i, err)
		}

		// Compare as normalized JSON objects to handle field ordering
		var origMap, rtMap map[string]interface{}
		if err := json.Unmarshal(origJSON, &origMap); err != nil {
			t.Fatalf("Failed to unmarshal original JSON: %v", err)
		}
		if err := json.Unmarshal(rtJSON, &rtMap); err != nil {
			t.Fatalf("Failed to unmarshal round-tripped JSON: %v", err)
		}

		origNorm, _ := json.Marshal(origMap)
		rtNorm, _ := json.Marshal(rtMap)

		if !bytes.Equal(origNorm, rtNorm) {
			t.Errorf("Transparency entry %d mismatch:\nOriginal: %s\nRound-tripped: %s",
				i, string(origNorm), string(rtNorm))
		}
	}
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	// Read the original test data
	originalData, err := os.ReadFile(filepath.Join("..", "..", "testdata", "pypi.attestation.json"))
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	// Unmarshal to attestation
	attestation, err := UnmarshalAttestation(originalData)
	if err != nil {
		t.Fatalf("Failed to unmarshal attestation: %v", err)
	}

	// Marshal back to JSON
	marshaledData, err := MarshalAttestation(attestation)
	if err != nil {
		t.Fatalf("Failed to marshal attestation: %v", err)
	}

	// Unmarshal again
	roundTrippedAttestation, err := UnmarshalAttestation(marshaledData)
	if err != nil {
		t.Fatalf("Failed to unmarshal round-tripped data: %v", err)
	}

	// Compare certificates
	if !bytes.Equal(attestation.VerificationMaterial.Certificate,
		roundTrippedAttestation.VerificationMaterial.Certificate) {
		t.Error("Certificate mismatch after JSON round-trip")
	}

	// Compare envelope statement
	if !bytes.Equal(attestation.Envelope.Statement,
		roundTrippedAttestation.Envelope.Statement) {
		t.Error("Statement mismatch after JSON round-trip")
	}

	// Compare envelope signature
	if !bytes.Equal(attestation.Envelope.Signature,
		roundTrippedAttestation.Envelope.Signature) {
		t.Error("Signature mismatch after JSON round-trip")
	}
}

func TestBundleSerialization(t *testing.T) {
	// Read and unmarshal the test data
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "pypi.attestation.json"))
	if err != nil {
		t.Fatalf("Failed to read test data: %v", err)
	}

	attestation, err := UnmarshalAttestation(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal attestation: %v", err)
	}

	// Convert to bundle
	bundle, err := ToBundle(attestation)
	if err != nil {
		t.Fatalf("Failed to convert to bundle: %v", err)
	}

	// Verify media type is set
	expectedMediaType := "application/vnd.dev.sigstore.bundle.v0.3+json"
	if bundle.Bundle.MediaType != expectedMediaType {
		t.Errorf("Expected media type '%s', got '%s'", expectedMediaType, bundle.Bundle.MediaType)
	}

	// Marshal to JSON
	jsonBytes, err := MarshalBundle(bundle)
	if err != nil {
		t.Fatalf("Failed to marshal bundle: %v", err)
	}

	// Verify JSON contains mediaType
	var bundleMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &bundleMap); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	mediaType, ok := bundleMap["mediaType"].(string)
	if !ok || mediaType != expectedMediaType {
		t.Errorf("JSON mediaType incorrect: expected '%s', got '%s'", expectedMediaType, mediaType)
	}

	// Unmarshal back from JSON
	roundTrippedBundle, err := UnmarshalBundle(jsonBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal bundle: %v", err)
	}

	// Verify media type is preserved
	if roundTrippedBundle.Bundle.MediaType != expectedMediaType {
		t.Errorf("Round-tripped media type incorrect: expected '%s', got '%s'",
			expectedMediaType, roundTrippedBundle.Bundle.MediaType)
	}
}

func TestInvalidInputs(t *testing.T) {
	t.Run("nil attestation to ToBundle", func(t *testing.T) {
		_, err := ToBundle(nil)
		if err == nil {
			t.Error("Expected error for nil attestation")
		}
	})

	t.Run("nil bundle to FromBundle", func(t *testing.T) {
		_, err := FromBundle(nil)
		if err == nil {
			t.Error("Expected error for nil bundle")
		}
	})

	t.Run("invalid version", func(t *testing.T) {
		attestation := &pb.Attestation{
			Version: 999,
			VerificationMaterial: &pb.VerificationMaterial{
				Certificate: []byte{0x01, 0x02},
			},
			Envelope: &pb.Envelope{
				Statement: []byte{0x03, 0x04},
				Signature: []byte{0x05, 0x06},
			},
		}
		_, err := ToBundle(attestation)
		if err == nil {
			t.Error("Expected error for invalid version")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := UnmarshalAttestation([]byte("not valid json"))
		if err == nil {
			t.Error("Expected error for invalid JSON")
		}
	})
}
