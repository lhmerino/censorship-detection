# Tripwire

Status Badges  
![Go](https://github.com/Kkevsterrr/censorship-detection/workflows/Go/badge.svg)

Bulk of the application that monitors live traffic and detects censorship flows

## Usage

### Build tripwire executable

	go build -o tripwire ./cmd/tripwire

### Print usage

	tripwire -h

### Run using the default config on specified pcap or interface

	tripwire [-pcap pcapfile | -iface interface]

### Run using a custom configuration

	tripwire -config config.yml

### Dump current config

	tripwire -dump-config > config.yml

### Run unit tests

	go test ./...

### Update test files

	go test ./cmd/tripwire -update
