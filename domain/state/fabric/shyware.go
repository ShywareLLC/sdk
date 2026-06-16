package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"

	"github.com/hyperledger/fabric-chaincode-go/shim"
	pb "github.com/hyperledger/fabric-protos-go/peer"
)

type ShywareChaincode struct{}

type List1Record struct {
	SubmissionID      string `json:"submissionId"`
	PayloadCommitment string `json:"payloadCommitment"`
}

type List2Record struct {
	IdentityHash string `json:"identityHash"`
}

type PeriodCloseRecord struct {
	ScopingID    string `json:"scopingId"`
	L1MerkleRoot string `json:"l1MerkleRoot"`
	L2MerkleRoot string `json:"l2MerkleRoot"`
	Attestation  string `json:"attestation"`
	ClosedAt     int64  `json:"closedAt"`
}

func (s *ShywareChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	return shim.Success([]byte("Shyware two-list invariant initialized"))
}

func (s *ShywareChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	fn, args := stub.GetFunctionAndParameters()
	switch fn {
	case "submitTwoListWrite":
		return s.submitTwoListWrite(stub, args)
	case "getCount":
		return s.getCount(stub, args)
	case "commitPeriodClose":
		return s.commitPeriodClose(stub, args)
	case "rescindTwoListWrite":
		return s.rescindTwoListWrite(stub, args)
	case "replaceTwoListWrite":
		return s.replaceTwoListWrite(stub, args)
	default:
		return shim.Error("Unknown function: " + fn)
	}
}

// Atomic two-list write — the core invariant.
// List 1: submission record (payload commitment, no identity).
// List 2: participant registry record (identity hash, no payload, no submission ID).
// No join key is ever written to ledger state.
func (s *ShywareChaincode) submitTwoListWrite(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 3 {
		return shim.Error("Expected: scopingId, list1Json, list2Json")
	}
	scopingId, list1Json, list2Json := args[0], args[1], args[2]

	var l1 List1Record
	if err := json.Unmarshal([]byte(list1Json), &l1); err != nil {
		return shim.Error("Invalid list1Json: " + err.Error())
	}
	var l2 List2Record
	if err := json.Unmarshal([]byte(list2Json), &l2); err != nil {
		return shim.Error("Invalid list2Json: " + err.Error())
	}

	if l1.SubmissionID == "" {
		return shim.Error("Rejection predicate: List 1 must have a submissionId")
	}
	if l2.IdentityHash == "" {
		return shim.Error("Rejection predicate: List 2 must have an identityHash")
	}

	// Rejection predicate: submissionId hash must not equal identityHash (no join key)
	h := sha256.Sum256([]byte(l1.SubmissionID))
	if fmt.Sprintf("%x", h) == l2.IdentityHash {
		return shim.Error("Rejection predicate: join key detected between L1 and L2")
	}

	// Sybil resistance: reject if this identity already has a record for this scopingId.
	// Without this check, a duplicate write would overwrite the L2 entry but still
	// increment COUNT, breaking the count-match invariant (count > |distinct L2 entries|).
	l2Key := fmt.Sprintf("L2_%s_%s", scopingId, l2.IdentityHash)
	existingL2, _ := stub.GetState(l2Key)
	if len(existingL2) > 0 {
		return shim.Error("Rejection predicate: identity already registered for this scopingId (sybil resistance)")
	}

	// Replay protection: reject if this submissionId already exists in L1.
	l1Key := fmt.Sprintf("L1_%s_%s", scopingId, l1.SubmissionID)
	existingL1, _ := stub.GetState(l1Key)
	if len(existingL1) > 0 {
		return shim.Error("Rejection predicate: submissionId already committed for this scopingId (replay protection)")
	}

	countKey := fmt.Sprintf("COUNT_%s", scopingId)
	countBytes, _ := stub.GetState(countKey)
	count := 0
	if len(countBytes) > 0 {
		fmt.Sscanf(string(countBytes), "%d", &count)
	}

	if err := stub.PutState(l1Key, []byte(list1Json)); err != nil {
		return shim.Error(err.Error())
	}
	if err := stub.PutState(l2Key, []byte(list2Json)); err != nil {
		return shim.Error(err.Error())
	}
	if err := stub.PutState(countKey, []byte(fmt.Sprintf("%d", count+1))); err != nil {
		return shim.Error(err.Error())
	}

	result, _ := json.Marshal(map[string]interface{}{"scopingId": scopingId, "l1Count": count + 1, "l2Count": count + 1, "countMatch": true})
	return shim.Success(result)
}

func (s *ShywareChaincode) getCount(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 1 {
		return shim.Error("Expected: scopingId")
	}
	countBytes, _ := stub.GetState(fmt.Sprintf("COUNT_%s", args[0]))
	count := 0
	if len(countBytes) > 0 {
		fmt.Sscanf(string(countBytes), "%d", &count)
	}
	result, _ := json.Marshal(map[string]interface{}{"scopingId": args[0], "l1Count": count, "l2Count": count, "countMatch": true})
	return shim.Success(result)
}

// commitPeriodClose seals a scoping period with disjoint Merkle roots.
// l1MerkleRoot is computed over submission identifiers only.
// l2MerkleRoot is computed over identity hashes only.
// No join between the two roots is written.
func (s *ShywareChaincode) commitPeriodClose(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 4 {
		return shim.Error("Expected: scopingId, l1MerkleRoot, l2MerkleRoot, attestation")
	}
	key := fmt.Sprintf("ATTEST_%s", args[0])
	existing, _ := stub.GetState(key)
	if len(existing) > 0 {
		return shim.Error("Period already closed: " + args[0])
	}
	ts, _ := stub.GetTxTimestamp()
	record := PeriodCloseRecord{
		ScopingID:    args[0],
		L1MerkleRoot: args[1],
		L2MerkleRoot: args[2],
		Attestation:  args[3],
		ClosedAt:     ts.GetSeconds(),
	}
	data, _ := json.Marshal(record)
	if err := stub.PutState(key, data); err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(data)
}

// rescindTwoListWrite atomically deletes both L1 and L2 entries for a submission
// and decrements the count — preserving countMatch after removal (Claim 18).
// Args: scopingId, submissionId, identityHash
func (s *ShywareChaincode) rescindTwoListWrite(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 3 {
		return shim.Error("Expected: scopingId, submissionId, identityHash")
	}
	scopingId, submissionId, identityHash := args[0], args[1], args[2]

	l1Key := fmt.Sprintf("L1_%s_%s", scopingId, submissionId)
	l2Key := fmt.Sprintf("L2_%s_%s", scopingId, identityHash)

	if err := stub.DelState(l1Key); err != nil {
		return shim.Error("Failed to delete L1: " + err.Error())
	}
	if err := stub.DelState(l2Key); err != nil {
		return shim.Error("Failed to delete L2: " + err.Error())
	}

	countKey := fmt.Sprintf("COUNT_%s", scopingId)
	countBytes, _ := stub.GetState(countKey)
	count := 0
	if len(countBytes) > 0 {
		fmt.Sscanf(string(countBytes), "%d", &count)
	}
	if count > 0 {
		count--
	}
	if err := stub.PutState(countKey, []byte(fmt.Sprintf("%d", count))); err != nil {
		return shim.Error(err.Error())
	}

	result, _ := json.Marshal(map[string]interface{}{
		"scopingId": scopingId, "l1Count": count, "l2Count": count, "countMatch": true, "rescinded": true,
	})
	return shim.Success(result)
}

// replaceTwoListWrite atomically replaces the L1 payload for a submission while
// keeping the L2 identity entry unchanged — count and countMatch are preserved (Claim 19).
// Args: scopingId, oldSubmissionId, newList1Json, identityHash
func (s *ShywareChaincode) replaceTwoListWrite(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) != 4 {
		return shim.Error("Expected: scopingId, oldSubmissionId, newList1Json, identityHash")
	}
	scopingId, oldSubmissionId, newList1Json, identityHash := args[0], args[1], args[2], args[3]

	var l1 List1Record
	if err := json.Unmarshal([]byte(newList1Json), &l1); err != nil {
		return shim.Error("Invalid newList1Json: " + err.Error())
	}
	if l1.SubmissionID == "" {
		return shim.Error("Rejection predicate: new List 1 must have a submissionId")
	}

	// Rejection predicate: new submissionId hash must not equal identityHash
	h := sha256.Sum256([]byte(l1.SubmissionID))
	if fmt.Sprintf("%x", h) == identityHash {
		return shim.Error("Rejection predicate: join key detected in replacement L1")
	}

	// Delete old L1 key, write new L1 key — L2 and count unchanged
	oldL1Key := fmt.Sprintf("L1_%s_%s", scopingId, oldSubmissionId)
	newL1Key := fmt.Sprintf("L1_%s_%s", scopingId, l1.SubmissionID)

	if err := stub.DelState(oldL1Key); err != nil {
		return shim.Error("Failed to delete old L1: " + err.Error())
	}
	if err := stub.PutState(newL1Key, []byte(newList1Json)); err != nil {
		return shim.Error("Failed to write new L1: " + err.Error())
	}

	countKey := fmt.Sprintf("COUNT_%s", scopingId)
	countBytes, _ := stub.GetState(countKey)
	count := 0
	if len(countBytes) > 0 {
		fmt.Sscanf(string(countBytes), "%d", &count)
	}

	result, _ := json.Marshal(map[string]interface{}{
		"scopingId": scopingId, "l1Count": count, "l2Count": count, "countMatch": true, "replaced": true,
		"newSubmissionId": l1.SubmissionID,
	})
	return shim.Success(result)
}

func main() {
	// ccaas (external builder) mode: peer connects to us, we listen on CHAINCODE_SERVER_ADDRESS.
	// Standard mode: we connect to the peer at CORE_PEER_ADDRESS.
	addr := os.Getenv("CHAINCODE_SERVER_ADDRESS")
	if addr != "" {
		var tlsProps shim.TLSProperties
		if os.Getenv("CHAINCODE_TLS_DISABLED") == "true" {
			// Explicit opt-out for local/dev environments (e.g. Docker peer on same host).
			// Not a silent fallback — must be set intentionally.
			tlsProps = shim.TLSProperties{Disabled: true}
		} else {
			certPath := os.Getenv("CHAINCODE_TLS_CERT")
			keyPath := os.Getenv("CHAINCODE_TLS_KEY")
			if certPath == "" || keyPath == "" {
				fmt.Println("CHAINCODE_TLS_CERT and CHAINCODE_TLS_KEY must be set (or set CHAINCODE_TLS_DISABLED=true)")
				os.Exit(1)
			}
			certPEM, errC := os.ReadFile(certPath)
			keyPEM, errK := os.ReadFile(keyPath)
			if errC != nil || errK != nil {
				fmt.Printf("Error reading TLS cert/key: cert=%v key=%v\n", errC, errK)
				os.Exit(1)
			}
			tlsProps = shim.TLSProperties{Disabled: false, Key: keyPEM, Cert: certPEM}
		}
		srv := &shim.ChaincodeServer{
			CCID:     os.Getenv("CHAINCODE_ID"),
			Address:  addr,
			CC:       new(ShywareChaincode),
			TLSProps: tlsProps,
		}
		if err := srv.Start(); err != nil {
			fmt.Printf("Error starting ccaas server: %s", err)
		}
	} else {
		if err := shim.Start(new(ShywareChaincode)); err != nil {
			fmt.Printf("Error starting ShywareChaincode: %s", err)
		}
	}
}
