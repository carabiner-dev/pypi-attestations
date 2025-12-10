package convert

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	pb "github.com/carabiner-dev/pypi-attestations/proto"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	protorekor "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

// ToBundle converts a PyPI attestation (PEP 740) to a Sigstore Bundle.
func ToBundle(attestation *pb.Attestation) (*bundle.Bundle, error) {
	if attestation == nil {
		return nil, fmt.Errorf("attestation cannot be nil")
	}

	if attestation.Version != 1 {
		return nil, fmt.Errorf("unsupported attestation version: %d", attestation.Version)
	}

	// Parse the certificate
	cert, err := x509.ParseCertificate(attestation.VerificationMaterial.Certificate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Create DSSE envelope
	envelope := &protodsse.Envelope{
		Payload:     attestation.Envelope.Statement,
		PayloadType: "application/vnd.in-toto+json",
		Signatures: []*protodsse.Signature{
			{
				Sig: attestation.Envelope.Signature,
			},
		},
	}

	// Parse the transparency log entry
	if len(attestation.VerificationMaterial.TransparencyEntries) == 0 {
		return nil, fmt.Errorf("no transparency entries found")
	}

	tlogEntry, err := transparencyEntryFromStruct(attestation.VerificationMaterial.TransparencyEntries[0])
	if err != nil {
		return nil, fmt.Errorf("failed to convert transparency entry: %w", err)
	}

	// Create the Sigstore bundle protobuf
	pbBundle := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{
					RawBytes: cert.Raw,
				},
			},
			TlogEntries: []*protorekor.TransparencyLogEntry{tlogEntry},
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: envelope,
		},
	}

	// Wrap in bundle.Bundle
	return bundle.NewBundle(pbBundle)
}

// FromBundle converts a Sigstore Bundle to a PyPI attestation (PEP 740).
func FromBundle(b *bundle.Bundle) (*pb.Attestation, error) {
	if b == nil || b.Bundle == nil {
		return nil, fmt.Errorf("bundle cannot be nil")
	}

	// Extract certificate
	var certBytes []byte
	switch content := b.Bundle.VerificationMaterial.Content.(type) {
	case *protobundle.VerificationMaterial_Certificate:
		certBytes = content.Certificate.RawBytes
	case *protobundle.VerificationMaterial_X509CertificateChain:
		if len(content.X509CertificateChain.Certificates) == 0 {
			return nil, fmt.Errorf("no certificates in chain")
		}
		certBytes = content.X509CertificateChain.Certificates[0].RawBytes
	default:
		return nil, fmt.Errorf("unsupported certificate type")
	}

	// Extract DSSE envelope
	dsseEnvelope, ok := b.Bundle.Content.(*protobundle.Bundle_DsseEnvelope)
	if !ok {
		return nil, fmt.Errorf("bundle does not contain a DSSE envelope")
	}

	if len(dsseEnvelope.DsseEnvelope.Signatures) != 1 {
		return nil, fmt.Errorf("expected exactly one signature, got %d", len(dsseEnvelope.DsseEnvelope.Signatures))
	}

	// Convert transparency log entries
	tlogEntries := make([]*structpb.Struct, len(b.Bundle.VerificationMaterial.TlogEntries))
	for i, entry := range b.Bundle.VerificationMaterial.TlogEntries {
		s, err := transparencyEntryToStruct(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to convert transparency entry %d: %w", i, err)
		}
		tlogEntries[i] = s
	}

	attestation := &pb.Attestation{
		Version: 1,
		VerificationMaterial: &pb.VerificationMaterial{
			Certificate:         certBytes,
			TransparencyEntries: tlogEntries,
		},
		Envelope: &pb.Envelope{
			Statement: dsseEnvelope.DsseEnvelope.Payload,
			Signature: dsseEnvelope.DsseEnvelope.Signatures[0].Sig,
		},
	}

	return attestation, nil
}

// transparencyEntryToStruct converts a Rekor TransparencyLogEntry to a structpb.Struct.
func transparencyEntryToStruct(entry *protorekor.TransparencyLogEntry) (*structpb.Struct, error) {
	// Marshal to JSON
	jsonBytes, err := protojson.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal transparency entry to JSON: %w", err)
	}

	// Unmarshal to map
	var m map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &m); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to map: %w", err)
	}

	// Convert to structpb.Struct
	s, err := structpb.NewStruct(m)
	if err != nil {
		return nil, fmt.Errorf("failed to create structpb.Struct: %w", err)
	}

	return s, nil
}

// transparencyEntryFromStruct converts a structpb.Struct to a Rekor TransparencyLogEntry.
func transparencyEntryFromStruct(s *structpb.Struct) (*protorekor.TransparencyLogEntry, error) {
	// Marshal to JSON
	jsonBytes, err := protojson.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal struct to JSON: %w", err)
	}

	// Unmarshal to TransparencyLogEntry
	var entry protorekor.TransparencyLogEntry
	if err := protojson.Unmarshal(jsonBytes, &entry); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to TransparencyLogEntry: %w", err)
	}

	return &entry, nil
}

// MarshalBundle marshals a Sigstore Bundle to JSON.
func MarshalBundle(b *bundle.Bundle) ([]byte, error) {
	if b == nil || b.Bundle == nil {
		return nil, fmt.Errorf("bundle cannot be nil")
	}

	return protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(b.Bundle)
}

// UnmarshalBundle unmarshals JSON to a Sigstore Bundle.
func UnmarshalBundle(data []byte) (*bundle.Bundle, error) {
	pbBundle := &protobundle.Bundle{}
	if err := protojson.Unmarshal(data, pbBundle); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bundle JSON: %w", err)
	}

	return bundle.NewBundle(pbBundle)
}

// MarshalAttestation marshals an Attestation to JSON in PEP 740 format.
func MarshalAttestation(attestation *pb.Attestation) ([]byte, error) {
	// Create a map for custom JSON marshaling to handle base64 encoding
	result := map[string]interface{}{
		"version": attestation.Version,
		"verification_material": map[string]interface{}{
			"certificate":          base64.StdEncoding.EncodeToString(attestation.VerificationMaterial.Certificate),
			"transparency_entries": attestation.VerificationMaterial.TransparencyEntries,
		},
		"envelope": map[string]interface{}{
			"statement": base64.StdEncoding.EncodeToString(attestation.Envelope.Statement),
			"signature": base64.StdEncoding.EncodeToString(attestation.Envelope.Signature),
		},
	}

	return json.MarshalIndent(result, "", "  ")
}

// UnmarshalAttestation unmarshals JSON in PEP 740 format to an Attestation.
func UnmarshalAttestation(data []byte) (*pb.Attestation, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON: %w", err)
	}

	attestation := &pb.Attestation{
		VerificationMaterial: &pb.VerificationMaterial{},
		Envelope:             &pb.Envelope{},
	}

	// Parse version
	if v, ok := raw["version"].(float64); ok {
		attestation.Version = uint32(v)
	}

	// Parse verification material
	if vm, ok := raw["verification_material"].(map[string]interface{}); ok {
		if certStr, ok := vm["certificate"].(string); ok {
			cert, err := base64.StdEncoding.DecodeString(certStr)
			if err != nil {
				return nil, fmt.Errorf("failed to decode certificate: %w", err)
			}
			attestation.VerificationMaterial.Certificate = cert
		}

		if entries, ok := vm["transparency_entries"].([]interface{}); ok {
			for _, entry := range entries {
				if entryMap, ok := entry.(map[string]interface{}); ok {
					s, err := structpb.NewStruct(entryMap)
					if err != nil {
						return nil, fmt.Errorf("failed to create transparency entry struct: %w", err)
					}
					attestation.VerificationMaterial.TransparencyEntries = append(
						attestation.VerificationMaterial.TransparencyEntries,
						s,
					)
				}
			}
		}
	}

	// Parse envelope
	if env, ok := raw["envelope"].(map[string]interface{}); ok {
		if stmtStr, ok := env["statement"].(string); ok {
			stmt, err := base64.StdEncoding.DecodeString(stmtStr)
			if err != nil {
				return nil, fmt.Errorf("failed to decode statement: %w", err)
			}
			attestation.Envelope.Statement = stmt
		}

		if sigStr, ok := env["signature"].(string); ok {
			sig, err := base64.StdEncoding.DecodeString(sigStr)
			if err != nil {
				return nil, fmt.Errorf("failed to decode signature: %w", err)
			}
			attestation.Envelope.Signature = sig
		}
	}

	return attestation, nil
}
