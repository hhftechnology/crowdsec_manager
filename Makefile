.PHONY: contracts

contracts:
	GOCACHE=$${GOCACHE:-/tmp/go-build} go run ./pkg/contracts/cmd/contractsgen
