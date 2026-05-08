package cve

import "testing"

func TestLookupWithoutVersionDoesNotReturnUnqualifiedCVEs(t *testing.T) {
	res := Lookup("nginx", "")
	if len(res.CVEs) != 0 {
		t.Fatalf("expected no CVEs without version evidence, got %#v", res.CVEs)
	}
}

func TestContainsVersionToken(t *testing.T) {
	if !containsVersionToken("affected version 1.24.0 allows exposure", "1.24.0") {
		t.Fatal("expected exact version token match")
	}
	if containsVersionToken("affected version 11.24.0 allows exposure", "1.24.0") {
		t.Fatal("did not expect partial version token match")
	}
}
