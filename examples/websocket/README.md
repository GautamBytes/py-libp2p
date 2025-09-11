# WebSocket Transport Examples

This directory contains examples demonstrating the WebSocket transport functionality in py-libp2p.

## Features Demonstrated

- **WebSocket Transport**: Basic WebSocket connectivity with `/ws` multiaddrs
- **Security Integration**: Noise encryption by default for secure communication  
- **IPv6 Support**: Proper handling of IPv6 addresses in WebSocket URLs
- **DNS Support**: Support for DNS addresses (dns4, dns6, dnsaddr)
- **Cross-platform Interoperability**: Compatible with js-libp2p and go-libp2p WebSocket implementations

## Prerequisites

Install the WebSocket dependencies:

```bash
pip install trio-websocket
```

## Examples

### 1. WebSocket Echo Demo (`websocket_echo_demo.py`)

A comprehensive example showing WebSocket transport with security.

**Start a server:**
```bash
# IPv4 server
python websocket_echo_demo.py -l /ip4/0.0.0.0/tcp/8080/ws

# IPv6 server  
python websocket_echo_demo.py -l /ip6/::/tcp/8080/ws

# Localhost server
python websocket_echo_demo.py -l /ip4/127.0.0.1/tcp/8080/ws
```

**Connect a client:**
```bash  
python websocket_echo_demo.py -d /ip4/127.0.0.1/tcp/8080/ws/p2p/<PEER_ID>
```

The demo includes:
- ✅ **Noise encryption** by default for secure communication
- ✅ **Echo protocol** demonstrating bi-directional communication
- ✅ **IPv6 address support** with proper URL formatting
- ✅ **Error handling** and connection lifecycle management
- ✅ **Detailed logging** for debugging and understanding

## Key Security Features

### Noise Protocol Encryption

By default, all WebSocket connections use the **Noise protocol** for encryption:

```python
# Noise encryption is enabled by default in new_host()
host = new_host(listen_addrs=[ws_addr])  # Includes Noise security
```

### Multiple Security Protocols

The WebSocket transport supports all libp2p security protocols:

- **Noise** (default, recommended)
- **SECIO** (legacy)
- **Plaintext** (insecure, for testing only)

### IPv6 and DNS Support

The implementation correctly handles various address types:

```python
# IPv4
/ip4/127.0.0.1/tcp/8080/ws

# IPv6 (automatically wrapped in brackets for WebSocket URLs)  
/ip6/::1/tcp/8080/ws          -> ws://[::1]:8080/

# DNS
/dns4/example.com/tcp/443/ws  -> ws://example.com:443/
/dns6/example.com/tcp/443/ws  -> ws://example.com:443/
```

## Integration with js-libp2p

The WebSocket transport is fully compatible with js-libp2p:

**js-libp2p server:**
```javascript
import { createLibp2p } from 'libp2p'
import { webSockets } from '@libp2p/websockets'
import { noise } from '@chainsafe/libp2p-noise'

const node = await createLibp2p({
  transports: [webSockets()],
  connectionEncryption: [noise()],
  addresses: {
    listen: ['/ip4/0.0.0.0/tcp/8080/ws']
  }
})
```

**py-libp2p client:**
```bash
python websocket_echo_demo.py -d /ip4/127.0.0.1/tcp/8080/ws/p2p/<JS_PEER_ID>
```

## Transport Registry Integration

The WebSocket transport automatically integrates with py-libp2p's new transport registry:

```python
from libp2p import new_host
from multiaddr import Multiaddr

# Automatically selects WebSocket transport for /ws addresses
ws_addr = Multiaddr("/ip4/127.0.0.1/tcp/8080/ws") 
host = new_host(listen_addrs=[ws_addr])  # Uses WebsocketTransport

# Automatically selects TCP transport for TCP-only addresses
tcp_addr = Multiaddr("/ip4/127.0.0.1/tcp/8080")
host = new_host(listen_addrs=[tcp_addr])  # Uses TCP transport
```

## Troubleshooting

### Missing Dependencies

If you see import errors:
```bash
pip install trio-websocket
```

### IPv6 Connection Issues

Ensure your system supports IPv6 and the address is correctly formatted:
```python
# Correct IPv6 format
/ip6/::1/tcp/8080/ws

# WebSocket URL is automatically formatted as: ws://[::1]:8080/
```

### Security Protocol Mismatches

Both peers must support compatible security protocols. The default Noise protocol should work with most libp2p implementations.

## Future Enhancements

- [ ] **Secure WebSocket (/wss)**: TLS support for WebSocket transport
- [ ] **WebRTC Integration**: Browser-to-server and private-to-private WebRTC
- [ ] **Performance Optimization**: Buffering and connection pooling improvements