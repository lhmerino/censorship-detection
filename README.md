# Tripwire

Status Badges  
![Go](https://github.com/Kkevsterrr/censorship-detection/workflows/Go/badge.svg)

Bulk of the application that monitors live traffic and detects censorship flows

## Usage

### Build tripwire executable

	go build -o tripwire ./cmd/tripwire

### Run using the default config

	tripwire -iface eth0

### Run using a custom configuration

	tripwire -config config.yml

### Dump default configuration

	tripwire -dump-config > config.yml

### Run unit tests

	go test ./...

### Update test files

	go test ./cmd/tripwire -update
