# HTTP Sink for Halon API Testing

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
