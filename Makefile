.PHONY: lint
lint:
	if [ -z "$(shell which pre-commit)" ]; then pip3 install pre-commit; fi
	pre-commit install
	pre-commit run --all-files

.PHONY: test
test:
	go test -race -v ./...

.PHONY: verify
verify:
	go mod download
	go mod verify
