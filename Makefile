.PHONY: lint lint-fix lint-format lint-install lint-list

lint-install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v2.5.0

# Показать доступные линтеры
lint-list:
	golangci-lint help linters

# Только проверка
lint:
	golangci-lint run ./...

# Исправить линтеры
lint-fix:
	golangci-lint run --fix ./...

# Проверить только изменения в PR
lint-diff:
	golangci-lint run --new-from-rev=HEAD~1 ./...

# Быстрая проверка одного пакета
lint-secret:
	golangci-lint run ./internal/secret/...