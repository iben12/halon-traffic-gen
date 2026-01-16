# SMPT/HTTP Email Traffic Generator for Halon MTA

Inspired by KumoMTA `traffic-gen` ([source code](https://github.com/KumoCorp/kumomta/tree/main/crates/traffic-gen)) rewritten in Go and HTTP API calls adjusted to Halon MTA spec.

```txt
Usage of ./traffic-gen:
  -api-key string
        API key for HTTP submission (X-API-Key header)
  -body-file string
        Take the message contents from the specified file
  -body-size int
        When generating the body, use at least this many bytes (default 1024)
  -concurrency int
        The number of connections to open to target (0 = auto)
  -domain value
        Domain to use (can be specified multiple times)
  -domain-suffix string
        All generated mail will have this domain appended (default "mx-sink.wezfurlong.org")
  -duration int
        How many seconds to generate for (default 60)
  -header value
        Custom header to add (can be specified multiple times)
  -http
        Use http injection API instead of SMTP
  -http-batch-size int
        When using http injection, how many recipients to generate in a single request (default 1)
  -http-defer-generation
        When using http injection, enable deferred_generation
  -http-defer-spool
        When using http injection, enable deferred_spool
  -keep-going
        Continue sending even if errors are returned by the target
  -message-count int
        Generate exactly this many messages instead of running for duration
  -starttls
        Whether to use STARTTLS for submission
  -target string
        The target host to which mail will be submitted (default "127.0.0.1:2025")
  -throttle float
        Limit the sending rate to the specified rate (msgs/sec, 0 = unlimited)
```

## HTTP Sink for Halon API Testing

A simple HTTP server that implements the Halon `/v1/submission` endpoint for testing the traffic generator.

## Features

- Implements Halon HTTP submission API (multipart/form-data)
- Prints recipient addresses for each submission
- Returns proper JSON response with transaction ID
- Optional verbose mode to print full message bodies
- Optional API key authentication
- Supports `?pretty=true` query parameter for formatted JSON responses

## Usage

```bash
# Build
cd http-sink
go mod tidy
go build -o http-sink main.go

# Run with defaults (port 80, no auth)
./http-sink

# Run on custom port
./http-sink -port 8080

# Enable verbose logging (prints message bodies)
./http-sink -verbose

# Enable API key authentication
./http-sink -api-key badsecret

# Combine options
./http-sink -port 8080 -api-key mykey -verbose
```

## Testing

```bash
# Start the sink
./http-sink -port 8080 -verbose

# In another terminal, run the traffic generator
cd ..
./traffic-gen --http --target http://localhost:8080 --duration 5 --concurrency 2
```

## Response Format

The server returns a JSON response following the Halon specification:

```json
{
  "result": {
    "code": 250,
    "enhanced": [2, 0, 0],
    "reason": ["Ok: queued as 7c9e67bb-661f-4ccb-b8ee-521a0e723324"]
  },
  "transaction": {
    "id": "7c9e67bb-661f-4ccb-b8ee-521a0e723324"
  },
  "metadata": {}
}
```
