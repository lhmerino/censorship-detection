# Censorship Detection

Status Badges  
![Go](https://github.com/Kkevsterrr/censorship-detection/workflows/Go/badge.svg)

## App

Bulk of the application that monitors live traffic and detects censorship flows

### Configuration:
- app/config/config.yml

### Run

Demo run (pcap) of a censored flow

```shell script
cd censorship-detection/app
go build -o ../build/measurement .
cd ..
./build/measurement -config_file app/config/config.yml
```

### Tests

```shell script
cd censorship-detection/app/tests
go test
```

