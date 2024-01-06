FROM mcr.microsoft.com/devcontainers/go:1-1.21-bookworm

USER vscode
RUN go install github.com/mitranim/gow@latest
RUN go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
USER root
