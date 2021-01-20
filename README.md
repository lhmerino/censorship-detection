# Tripwire

Status Badges  
![Go](https://github.com/Kkevsterrr/censorship-detection/workflows/Go/badge.svg)

## App

Bulk of the application that monitors live traffic and detects censorship flows

### Configuration
- config/config.yml

### Run

Demo run (pcap) of a censored flow

```shell script
go build -o ./bin/tripwire ./cmd/tripwire
bin/tripwire -config configs/config.yml
```

### Tests

```shell script
go test ./...
```

