package contracts

import "testing"

func TestRawSyscallQueryStableInvocationContract(t *testing.T) {
	wire, err := NewInvestigationContracts()
	if err != nil {
		t.Fatal(err)
	}
	// A missing grant reaches the ordinary review remedy, never a worker read.
	// Admission still requires the exact current syscall-query grant.
	input := []byte(`{"case_id":"00000000-0000-4000-8000-000000000022","artifact_id":"00000000-0000-4000-8000-000000000023","idempotency_key":"original-syscall-page","limit":20,"syscall_names":["write"],"errors_only":true}`)
	if err := wire.ValidateInput("syscall_query", input); err != nil {
		t.Fatal("bounded raw query with its stable key must reach review", err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"case_id":"00000000-0000-4000-8000-000000000022","artifact_id":"00000000-0000-4000-8000-000000000023","grant_id":"00000000-0000-4000-8000-000000000024"}`),
		[]byte(`{"case_id":"00000000-0000-4000-8000-000000000022","artifact_id":"00000000-0000-4000-8000-000000000023","idempotency_key":"key","argument_expression":"*address"}`),
	} {
		if wire.ValidateInput("syscall_query", invalid) == nil {
			t.Fatal("missing stable key or arbitrary expression accepted")
		}
	}
}
