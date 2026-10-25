package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

// ============================================================
// DECRYPTION RECORD
// ============================================================

type DecryptionRecord struct {
	RecipientID     string `json:"recipientID,omitempty"`
	RecipientIDHash string `json:"recipientIDHash,omitempty"`
	DocumentHash    string `json:"documentHash"`
	Timestamp       string `json:"timestamp"`
	WatermarkID     string `json:"watermarkID"`
	DilithiumSig    string `json:"dilithiumSig"`
	ZKPProof        string `json:"zkpProof,omitempty"`
	TxID            string `json:"txID"`
}

// ============================================================
// KEY REVOCATION
// ============================================================

type KeyRevocation struct {
	RecipientID     string `json:"recipientID,omitempty"`
	RecipientIDHash string `json:"recipientIDHash,omitempty"`
	KeyID           string `json:"keyID"`
	Reason          string `json:"reason,omitempty"`
	Timestamp       string `json:"timestamp"`
	ZKPProof        string `json:"zkpProof,omitempty"`
	TxID            string `json:"txID"`
	Revoked         bool   `json:"revoked"`
}

// ============================================================
// SMART CONTRACT
// ============================================================

type SmartContract struct {
	contractapi.Contract
}

// ============================================================
// 1. RECORD DECRYPTION
// ============================================================

func (s *SmartContract) RecordDecryption(
	ctx contractapi.TransactionContextInterface,
	recordJSON string,
) error {

	var record DecryptionRecord

	err := json.Unmarshal([]byte(recordJSON), &record)
	if err != nil {
		return fmt.Errorf("invalid decryption record JSON: %v", err)
	}

	if record.DocumentHash == "" {
		return fmt.Errorf("documentHash is required")
	}

	if record.WatermarkID == "" {
		return fmt.Errorf("watermarkID is required")
	}

	// Recipient identity is optional for privacy-preserving records.
	// If neither recipient field is supplied, require a proof payload.
	if record.RecipientID == "" && record.RecipientIDHash == "" && record.ZKPProof == "" {
		return fmt.Errorf("zkpProof is required when recipientID and recipientIDHash are omitted")
	}

	// Generate timestamp if not provided.
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	// A watermark ID is write-once. Check it before preparing any writes.
	watermarkKey := "watermark_" + record.WatermarkID
	existing, err := ctx.GetStub().GetState(watermarkKey)
	if err != nil {
		return fmt.Errorf("failed to check existing watermark: %v", err)
	}
	if len(existing) != 0 {
		return fmt.Errorf("watermarkID %s already exists", record.WatermarkID)
	}

	// Get Fabric transaction ID.
	record.TxID = ctx.GetStub().GetTxID()

	// Store the main record using transaction ID.
	recordKey := "decryption_" + record.TxID

	recordBytes, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to marshal decryption record: %v", err)
	}

	err = ctx.GetStub().PutState(recordKey, recordBytes)
	if err != nil {
		return fmt.Errorf("failed to store decryption record: %v", err)
	}

	// Store watermark index after confirming the ID is unused.
	err = ctx.GetStub().PutState(
		watermarkKey,
		recordBytes,
	)
	if err != nil {
		return fmt.Errorf("failed to store watermark index: %v", err)
	}

	// Emit Fabric event.
	err = ctx.GetStub().SetEvent(
		"DecryptionRecorded",
		recordBytes,
	)
	if err != nil {
		return fmt.Errorf("failed to emit decryption event: %v", err)
	}

	return nil
}

// ============================================================
// 2. QUERY BY WATERMARK
// ============================================================

func (s *SmartContract) QueryByWatermark(
	ctx contractapi.TransactionContextInterface,
	watermarkID string,
) (string, error) {

	if watermarkID == "" {
		return "", fmt.Errorf("watermarkID is required")
	}

	watermarkKey := "watermark_" + watermarkID

	recordBytes, err := ctx.GetStub().GetState(watermarkKey)

	if err != nil {
		return "", fmt.Errorf("failed to read watermark: %v", err)
	}

	if len(recordBytes) == 0 {
		return "", fmt.Errorf(
			"no decryption record found for watermark %s",
			watermarkID,
		)
	}

	return string(recordBytes), nil
}

// ============================================================
// 3. RECORD KEY REVOCATION
// ============================================================

func (s *SmartContract) RecordKeyRevocation(
	ctx contractapi.TransactionContextInterface,
	revocationJSON string,
) error {

	var revocation KeyRevocation

	err := json.Unmarshal(
		[]byte(revocationJSON),
		&revocation,
	)

	if err != nil {
		return fmt.Errorf(
			"invalid revocation JSON: %v",
			err,
		)
	}

	if revocation.KeyID == "" {
		return fmt.Errorf("keyID is required")
	}

	if revocation.RecipientID == "" &&
		revocation.RecipientIDHash == "" {
		return fmt.Errorf(
			"recipientID or recipientIDHash is required",
		)
	}

	if revocation.Timestamp == "" {
		revocation.Timestamp =
			time.Now().UTC().Format(time.RFC3339)
	}

	revocation.TxID = ctx.GetStub().GetTxID()
	revocation.Revoked = true

	revocationBytes, err := json.Marshal(revocation)

	if err != nil {
		return fmt.Errorf(
			"failed to marshal revocation: %v",
			err,
		)
	}

	// Use recipient ID when available.
	// Privacy-first deployments should use RecipientIDHash.
	var revocationKey string

	if revocation.RecipientIDHash != "" {
		revocationKey =
			"revocation_hash_" +
				revocation.RecipientIDHash
	} else {
		revocationKey =
			"revocation_" +
				revocation.RecipientID
	}

	err = ctx.GetStub().PutState(
		revocationKey,
		revocationBytes,
	)

	if err != nil {
		return fmt.Errorf(
			"failed to store revocation: %v",
			err,
		)
	}

	err = ctx.GetStub().SetEvent(
		"KeyRevoked",
		revocationBytes,
	)

	if err != nil {
		return fmt.Errorf(
			"failed to emit revocation event: %v",
			err,
		)
	}

	return nil
}

// ============================================================
// 4. QUERY KEY REVOCATION
// ============================================================

func (s *SmartContract) QueryKeyRevocation(
	ctx contractapi.TransactionContextInterface,
	recipientID string,
) (string, error) {

	if recipientID == "" {
		return "", fmt.Errorf("recipientID is required")
	}

	// The argument may be a plain recipient ID or a recipient hash.
	// Check both supported key namespaces for compatibility.
	keys := []string{
		"revocation_" + recipientID,
		"revocation_hash_" + recipientID,
	}
	for _, key := range keys {
		recordBytes, err := ctx.GetStub().GetState(key)
		if err != nil {
			return "", fmt.Errorf("failed to query revocation key %s: %v", key, err)
		}
		if len(recordBytes) != 0 {
			return string(recordBytes), nil
		}
	}
	return "", fmt.Errorf("no revocation record found for recipient ID or hash %s", recipientID)
}

// ============================================================
// 5. GET DECRYPTION HISTORY
// ============================================================

func (s *SmartContract) GetDecryptionHistory(
	ctx contractapi.TransactionContextInterface,
	documentHash string,
) (string, error) {

	if documentHash == "" {
		return "", fmt.Errorf("documentHash is required")
	}

	iterator, err :=
		ctx.GetStub().GetStateByRange(
			"decryption_",
			"decryption_\uffff",
		)

	if err != nil {
		return "", fmt.Errorf(
			"failed to query decryption records: %v",
			err,
		)
	}

	defer iterator.Close()

	var results []DecryptionRecord

	for iterator.HasNext() {

		item, err := iterator.Next()

		if err != nil {
			return "", fmt.Errorf(
				"failed to read ledger record: %v",
				err,
			)
		}

		var record DecryptionRecord

		err = json.Unmarshal(
			item.Value,
			&record,
		)

		if err != nil {
			continue
		}

		if record.DocumentHash == documentHash {
			results = append(results, record)
		}
	}

	resultBytes, err := json.Marshal(results)

	if err != nil {
		return "", fmt.Errorf(
			"failed to marshal history: %v",
			err,
		)
	}

	return string(resultBytes), nil
}

// ============================================================
// 6. GET RECENT DECRYPTIONS
// ============================================================

func (s *SmartContract) GetRecentDecryptions(
	ctx contractapi.TransactionContextInterface,
	limit string,
) (string, error) {

	limitValue := 50

	if limit != "" {

		parsed, err := strconv.Atoi(limit)

		if err != nil {
			return "", fmt.Errorf(
				"invalid limit: %v",
				err,
			)
		}

		if parsed <= 0 {
			return "", fmt.Errorf(
				"limit must be greater than zero",
			)
		}

		limitValue = parsed
	}

	iterator, err :=
		ctx.GetStub().GetStateByRange(
			"decryption_",
			"decryption_\uffff",
		)

	if err != nil {
		return "", fmt.Errorf(
			"failed to query decryptions: %v",
			err,
		)
	}

	defer iterator.Close()

	var results []DecryptionRecord

	for iterator.HasNext() {
		item, err := iterator.Next()

		if err != nil {
			return "", fmt.Errorf(
				"failed to read ledger record: %v",
				err,
			)
		}

		var record DecryptionRecord

		err = json.Unmarshal(
			item.Value,
			&record,
		)

		if err != nil {
			continue
		}

		results = append(results, record)
	}

	// Sort newest-first. RFC3339Nano supports timestamps with fractional seconds.
	sort.SliceStable(results, func(i, j int) bool {
		ti, errI := time.Parse(time.RFC3339Nano, results[i].Timestamp)
		tj, errJ := time.Parse(time.RFC3339Nano, results[j].Timestamp)
		if errI == nil && errJ == nil {
			return ti.After(tj)
		}
		// If a legacy timestamp is malformed, use string order as a stable fallback.
		return results[i].Timestamp > results[j].Timestamp
	})
	if len(results) > limitValue {
		results = results[:limitValue]
	}

	resultBytes, err := json.Marshal(results)

	if err != nil {
		return "", fmt.Errorf(
			"failed to marshal recent decryptions: %v",
			err,
		)
	}

	return string(resultBytes), nil
}

// ============================================================
// 7. VERIFY ZKP PROOF
// ============================================================
//
// IMPORTANT:
// This is currently a structural validation hook.
// It does NOT perform real cryptographic ZKP verification.
// A real circom/snarkjs verifier should be integrated
// outside the Fabric chaincode or through a deterministic
// verifier implementation.
//
// ============================================================

func (s *SmartContract) VerifyZKPProof(
	ctx contractapi.TransactionContextInterface,
	proof string,
) (string, error) {

	if proof == "" {
		return "", fmt.Errorf(
			"ZKP proof is empty",
		)
	}

	return "PLACEHOLDER ONLY: proof supplied; cryptographic ZKP verification was NOT performed", nil
}

// ============================================================
// 8. ATTRIBUTE WITHOUT REVEALING IDENTITY
// ============================================================

func (s *SmartContract) AttributeWithoutRevealing(
	ctx contractapi.TransactionContextInterface,
	watermarkID string,
	zkpProof string,
) (string, error) {

	if watermarkID == "" {
		return "", fmt.Errorf(
			"watermarkID is required",
		)
	}

	if zkpProof == "" {
		return "", fmt.Errorf(
			"zkpProof is required",
		)
	}

	recordBytes, err :=
		ctx.GetStub().GetState(
			"watermark_" + watermarkID,
		)

	if err != nil {
		return "", fmt.Errorf(
			"failed to query watermark: %v",
			err,
		)
	}

	if len(recordBytes) == 0 {
		return "", fmt.Errorf(
			"watermark record not found",
		)
	}

	return `{"placeholder":true,"attributed":false,"identityRevealed":false,"message":"No cryptographic attribution was performed"}`, nil
}

// ============================================================
// MAIN
// ============================================================

func main() {

	chaincode, err :=
		contractapi.NewChaincode(
			new(SmartContract),
		)

	if err != nil {
		panic(
			fmt.Sprintf(
				"Error creating chaincode: %v",
				err,
			),
		)
	}

	if err := chaincode.Start(); err != nil {
		panic(
			fmt.Sprintf(
				"Error starting chaincode: %v",
				err,
			),
		)
	}
}
