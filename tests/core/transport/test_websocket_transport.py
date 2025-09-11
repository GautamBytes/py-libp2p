"""Tests for WebSocket transport implementation."""

import pytest
from multiaddr import Multiaddr

from libp2p.crypto.secp256k1 import create_new_key_pair
from libp2p.custom_types import TProtocol
from libp2p.security.insecure.transport import InsecureTransport
from libp2p.stream_muxer.yamux.yamux import Yamux
from libp2p.transport.upgrader import TransportUpgrader

# Test if WebSocket dependencies are available
try:
    from libp2p.transport.websocket.transport import WebsocketTransport
    from libp2p.transport.websocket.listener import WebsocketListener
    from libp2p.transport.websocket.connection import P2PWebSocketConnection
    websocket_available = True
except ImportError:
    websocket_available = False

PLAINTEXT_PROTOCOL_ID = "/plaintext/2.0.0"


def create_test_upgrader():
    """Create a test transport upgrader with plaintext security."""
    key_pair = create_new_key_pair()
    return TransportUpgrader(
        secure_transports_by_protocol={
            TProtocol(PLAINTEXT_PROTOCOL_ID): InsecureTransport(key_pair)
        },
        muxer_transports_by_protocol={TProtocol("/yamux/1.0.0"): Yamux},
    )


@pytest.mark.skipif(not websocket_available, reason="WebSocket dependencies not available")
class TestWebsocketTransport:
    """Test the WebSocket transport implementation."""

    def test_websocket_transport_creation(self):
        """Test that WebSocket transport can be created."""
        upgrader = create_test_upgrader()
        transport = WebsocketTransport(upgrader)
        assert transport is not None
        assert hasattr(transport, 'dial')
        assert hasattr(transport, 'create_listener')

    def test_websocket_transport_requires_upgrader(self):
        """Test that WebSocket transport requires an upgrader."""
        with pytest.raises(TypeError):
            WebsocketTransport()  # Should fail without upgrader

    def test_websocket_listener_creation(self):
        """Test that WebSocket listener can be created."""
        upgrader = create_test_upgrader()
        transport = WebsocketTransport(upgrader)
        
        async def dummy_handler(conn):
            await conn.close()

        listener = transport.create_listener(dummy_handler)
        assert isinstance(listener, WebsocketListener)
        assert hasattr(listener, 'listen')
        assert hasattr(listener, 'close')
        assert hasattr(listener, 'get_addrs')

    def test_multiaddr_validation(self):
        """Test multiaddr validation for WebSocket transport."""
        upgrader = create_test_upgrader()
        transport = WebsocketTransport(upgrader)

        # Valid WebSocket multiaddrs
        valid_addrs = [
            "/ip4/127.0.0.1/tcp/8080/ws",
            "/ip6/::1/tcp/8080/ws",
            "/dns4/example.com/tcp/443/ws",
            "/dns6/example.com/tcp/443/ws",
        ]

        for addr_str in valid_addrs:
            maddr = Multiaddr(addr_str)
            # Should not raise exception during validation
            host = transport._extract_host_from_multiaddr(maddr)
            port = transport._extract_port_from_multiaddr(maddr)
            assert host is not None
            assert port > 0

    def test_invalid_multiaddr_handling(self):
        """Test handling of invalid multiaddrs."""
        upgrader = create_test_upgrader()
        transport = WebsocketTransport(upgrader)

        # Invalid multiaddrs
        invalid_addrs = [
            "/ip4/127.0.0.1/tcp/8080",  # No /ws
            "/ip4/127.0.0.1/ws",        # No /tcp
            "/tcp/8080/ws",             # No network protocol
        ]

        for addr_str in invalid_addrs:
            maddr = Multiaddr(addr_str)
            
            if not addr_str.endswith("/ws"):
                with pytest.raises(ValueError, match="only supports /ws addresses"):
                    transport.dial(maddr)
            else:
                with pytest.raises(ValueError, match="No"):
                    transport.dial(maddr)

    def test_ipv6_url_formatting(self):
        """Test that IPv6 addresses are properly formatted in WebSocket URLs."""
        upgrader = create_test_upgrader()
        transport = WebsocketTransport(upgrader)

        # Test IPv6 address formatting
        test_cases = [
            ("127.0.0.1", "ws://127.0.0.1:8080/"),      # IPv4 - no brackets
            ("::1", "ws://[::1]:8080/"),                 # IPv6 - add brackets
            ("[::1]", "ws://[::1]:8080/"),              # Already bracketed - keep brackets
            ("2001:db8::1", "ws://[2001:db8::1]:8080/"), # IPv6 - add brackets
            ("example.com", "ws://example.com:8080/"),   # Hostname - no brackets
        ]

        for host, expected_url in test_cases:
            url = transport._build_websocket_url(host, 8080)
            assert url == expected_url, f"For host '{host}', expected '{expected_url}', got '{url}'"

    def test_ipv6_detection(self):
        """Test IPv6 address detection logic."""
        upgrader = create_test_upgrader()
        transport = WebsocketTransport(upgrader)

        ipv6_addresses = [
            "::1",
            "2001:db8::1",
            "fe80::1%lo0",
            "::ffff:192.0.2.1",  # IPv4-mapped IPv6
        ]

        ipv4_and_hostnames = [
            "127.0.0.1",
            "192.168.1.1", 
            "example.com",
            "sub.example.com",
        ]

        for addr in ipv6_addresses:
            assert transport._is_ipv6_address(addr), f"Should detect '{addr}' as IPv6"

        for addr in ipv4_and_hostnames:
            assert not transport._is_ipv6_address(addr), f"Should not detect '{addr}' as IPv6"

    def test_wss_not_supported(self):
        """Test that WSS (secure WebSocket) is not yet supported."""
        upgrader = create_test_upgrader()
        transport = WebsocketTransport(upgrader)

        wss_addr = Multiaddr("/ip4/127.0.0.1/tcp/443/wss")
        
        with pytest.raises(NotImplementedError, match="/wss \\(TLS\\) not yet supported"):
            transport.dial(wss_addr)

    @pytest.mark.trio
    async def test_websocket_listener_close(self):
        """Test that WebSocket listener can be closed gracefully."""
        upgrader = create_test_upgrader()
        transport = WebsocketTransport(upgrader)

        async def dummy_handler(conn):
            await conn.close()

        listener = transport.create_listener(dummy_handler)
        
        # Test that close doesn't raise exception
        await listener.close()

    def test_connection_wrapper_interface(self):
        """Test that P2PWebSocketConnection implements required interface."""
        # Create a mock WebSocket connection
        class MockWebSocketConnection:
            def __init__(self):
                self.closed = False
                
            async def send_message(self, data):
                pass
                
            async def get_message(self):
                return b"test"
                
            async def aclose(self):
                self.closed = True

        mock_ws = MockWebSocketConnection()
        conn = P2PWebSocketConnection(mock_ws)

        # Test that it has the required interface methods
        assert hasattr(conn, 'read')
        assert hasattr(conn, 'write') 
        assert hasattr(conn, 'close')
        assert hasattr(conn, 'get_remote_address')


@pytest.mark.skipif(websocket_available, reason="Testing graceful handling when WebSocket not available")
class TestWebsocketTransportUnavailable:
    """Test behavior when WebSocket dependencies are not available."""

    def test_import_error_handling(self):
        """Test that import errors are handled gracefully."""
        # This test runs when trio-websocket is not available
        # The import should fail gracefully in transport registry
        from libp2p.transport.transport_registry import TransportRegistry
        
        registry = TransportRegistry()
        supported = registry.get_supported_protocols()
        
        # WebSocket should not be in supported protocols if dependencies missing
        assert "ws" not in supported or len([p for p in supported if p == "ws"]) == 0


class TestTransportRegistry:
    """Test the transport registry functionality."""

    def test_transport_registry_creation(self):
        """Test that transport registry can be created."""
        from libp2p.transport.transport_registry import TransportRegistry
        
        registry = TransportRegistry()
        assert registry is not None
        
        supported = registry.get_supported_protocols()
        assert "tcp" in supported  # TCP should always be supported

    def test_transport_registration(self):
        """Test registering custom transports."""
        from libp2p.transport.transport_registry import TransportRegistry
        from libp2p.abc import ITransport

        class CustomTransport(ITransport):
            async def dial(self, maddr):
                raise NotImplementedError
                
            def create_listener(self, handler):
                raise NotImplementedError

        registry = TransportRegistry()
        registry.register_transport("custom", CustomTransport)
        
        assert "custom" in registry.get_supported_protocols()
        assert registry.get_transport("custom") == CustomTransport

    def test_multiaddr_transport_selection(self):
        """Test automatic transport selection based on multiaddr."""
        from libp2p.transport.transport_registry import create_transport_for_multiaddr
        
        upgrader = create_test_upgrader()

        # Test TCP multiaddr
        tcp_addr = Multiaddr("/ip4/127.0.0.1/tcp/8080")
        tcp_transport = create_transport_for_multiaddr(tcp_addr, upgrader)
        assert tcp_transport is not None
        assert tcp_transport.__class__.__name__ == "TCP"

        if websocket_available:
            # Test WebSocket multiaddr
            ws_addr = Multiaddr("/ip4/127.0.0.1/tcp/8080/ws")
            ws_transport = create_transport_for_multiaddr(ws_addr, upgrader)
            assert ws_transport is not None
            assert ws_transport.__class__.__name__ == "WebsocketTransport"

        # Test unsupported multiaddr
        udp_addr = Multiaddr("/ip4/127.0.0.1/udp/8080")
        udp_transport = create_transport_for_multiaddr(udp_addr, upgrader)
        assert udp_transport is None

    def test_factory_function(self):
        """Test the create_transport factory function."""
        from libp2p.transport import create_transport
        
        upgrader = create_test_upgrader()

        # Test TCP transport creation
        tcp_transport = create_transport("tcp")
        assert tcp_transport is not None
        assert tcp_transport.__class__.__name__ == "TCP"

        if websocket_available:
            # Test WebSocket transport creation
            ws_transport = create_transport("ws", upgrader)
            assert ws_transport is not None
            assert ws_transport.__class__.__name__ == "WebsocketTransport"
            
            # Test that WebSocket requires upgrader
            with pytest.raises(ValueError, match="requires an upgrader"):
                create_transport("ws")

        # Test unsupported protocol
        with pytest.raises(ValueError, match="Unsupported transport protocol"):
            create_transport("unsupported")