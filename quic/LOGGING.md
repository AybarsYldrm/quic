# Logging

The whole stack uses one structured logger (`src/utils/logger.js`). Every
module gets a tag (`Connection`, `TLS`, `0-RTT`, `HTTP3`, `Gateway`,
`QPACK`, `Router`, `H2`, `Server`).

## Levels

| name  | value |
| ----- | ----- |
| ERROR | 0     |
| WARN  | 1     |
| INFO  | 2     |
| DEBUG | 3     |
| TRACE | 4     |

Default is `WARN`. Each level *includes* the lower ones, so `INFO` shows
errors, warnings and info lines.

## Activation

```bash
# everything from INFO upward
QUIC_LOG_LEVEL=INFO node h3Server.js

# everything (very chatty — every QUIC packet)
QUIC_LOG_LEVEL=DEBUG node h3Server.js

# bit-by-bit traces for the QPACK Huffman decoder etc.
QUIC_LOG_LEVEL=TRACE node h3Server.js
```

`QUIC_DEBUG` is a legacy alias for `QUIC_LOG_LEVEL` and accepts the same
values (including a numeric `0..4`).

## Filtering by module

```bash
# only logs from the TLS engine and the connection state machine
QUIC_LOG_LEVEL=DEBUG QUIC_LOG_MODULES=tls,connection node h3Server.js
```

Module names are case-insensitive.

## What you'll see at `INFO`

- Every QUIC connection `Connection established from <addr>:<port>`.
- The negotiated TLS cipher suite per handshake.
- 0-RTT acceptance / rejection (`0-RTT session ticket accepted`,
  `0-RTT denied (reason=...)`).
- One per-request HTTP access line with the encryption level the
  request rode on:
  ```
  [INFO] [Gateway] 0-RTT GET /api/me 200 12.3ms 88.236.187.193:34291
  [INFO] [Gateway] 1-RTT POST /api/login 200 41.8ms 88.236.187.193:34291
  ```

## Client-side logs

`h3Client.js`, `console/client.js`, and any code using `H3Connection.request`
emit one line per HTTP/3 round-trip:

```
[INFO] [HTTP3] H3 GET /api/info -> 200 124B 38.4ms
```

Set `QUIC_LOG_LEVEL=INFO` to see them.
