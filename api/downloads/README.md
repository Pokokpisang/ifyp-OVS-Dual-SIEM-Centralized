# OVS SIEM Agent Binary Distribution

Place the compiled Go agent binary here for the install script to serve:

```
downloads/
  ovs-agent-linux-amd64     # x86_64 Linux binary
```

## How to build and place the binary

From the project root:

```bash
cd agent
GOOS=linux GOARCH=amd64 go build -o ../api/downloads/ovs-agent-linux-amd64 ./cmd/agent/
```

The API automatically serves this file at:
  GET /downloads/ovs-agent-linux-amd64

## Note for FYP demo

The install.sh script skips the download step if `/usr/local/bin/ovs-agent` already exists on the target machine.
You can manually copy the binary there for local testing without needing this endpoint to be functional.
