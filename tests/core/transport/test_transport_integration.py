"""Integration tests for transport functionality."""

import pytest
from multiaddr import Multiaddr

from libp2p import new_host
from libp2p.crypto.secp256k1 import create_new_key_pair
from libp2p.custom_types import TProtocol
from libp2p.security.insecure.transport import InsecureTransport
from libp2p.stream_muxer.yamux.yamux import Yamux
from libp2p.transport.upgrader import TransportUpgrader

# Test if WebSocket dependencies are available
try:
    from libp2p.transport.websocket.transport import WebsocketTransport
    websocket_available = True
except ImportError:
    websocket_available = False

PLAINTEXT_PROTOCOL_ID = "/plaintext/2.0.0"
ECHO_PROTOCOL_ID = TProtocol("/echo/1.0.0")


class TestTransportIntegration:
    """Test transport integration with new_host function."""

    def test_tcp_transport_auto_selection(self):
        """Test that TCP transport is automatically selected for TCP addresses."""
        tcp_addr = Multiaddr("/ip4/127.0.0.1/tcp/0")
        
        # This should not raise an exception
        host = new_host(listen_addrs=[tcp_addr])
        assert host is not None
        
        # The swarm should have a TCP transport
        swarm = host.get_network()
        assert swarm.transport.__class__.__name__ == "TCP"

    @pytest.mark.skipif(not websocket_available, reason="WebSocket dependencies not available")
    def test_websocket_transport_auto_selection(self):
        """Test that WebSocket transport is automatically selected for WebSocket addresses."""
        ws_addr = Multiaddr("/ip4/127.0.0.1/tcp/0/ws")
        
        # This should not raise an exception
        host = new_host(listen_addrs=[ws_addr])
        assert host is not None
        
        # The swarm should have a WebSocket transport
        swarm = host.get_network()
        assert swarm.transport.__class__.__name__ == "WebsocketTransport"

    @pytest.mark.skipif(not websocket_available, reason="WebSocket dependencies not available") 
    def test_websocket_ipv6_address_support(self):
        """Test that WebSocket transport supports IPv6 addresses."""
        ipv6_addrs = [
            "/ip6/::1/tcp/0/ws",
            "/ip6/2001:db8::1/tcp/8080/ws",
        ]
        
        for addr_str in ipv6_addrs:
            ws_addr = Multiaddr(addr_str)
            
            # Should not raise an exception
            host = new_host(listen_addrs=[ws_addr])
            assert host is not None
            assert host.get_network().transport.__class__.__name__ == "WebsocketTransport"

    @pytest.mark.skipif(not websocket_available, reason="WebSocket dependencies not available")
    def test_websocket_dns_address_support(self):
        """Test that WebSocket transport supports DNS addresses."""
        dns_addrs = [
            "/dns4/localhost/tcp/8080/ws",
            "/dns6/localhost/tcp/8080/ws",
        ]
        
        for addr_str in dns_addrs:
            ws_addr = Multiaddr(addr_str)
            
            # Should not raise an exception
            host = new_host(listen_addrs=[ws_addr])
            assert host is not None
            assert host.get_network().transport.__class__.__name__ == "WebsocketTransport"

    def test_unsupported_transport_error(self):
        """Test that unsupported transports raise appropriate errors."""
        # UDP is not supported
        udp_addr = Multiaddr("/ip4/127.0.0.1/udp/8080")
        
        with pytest.raises(ValueError, match="Unknown transport in listen_addrs"):
            new_host(listen_addrs=[udp_addr])

    def test_quic_not_supported_error(self):
        """Test that QUIC raises not supported error."""
        quic_addr = Multiaddr("/ip4/127.0.0.1/udp/8080/quic")
        
        with pytest.raises(ValueError, match="QUIC not yet supported"):
            new_host(listen_addrs=[quic_addr])

    @pytest.mark.trio
    @pytest.mark.skipif(not websocket_available, reason="WebSocket dependencies not available")
    async def test_websocket_host_creation_and_cleanup(self):
        """Test WebSocket host can be created and cleaned up properly."""
        ws_addr = Multiaddr("/ip4/127.0.0.1/tcp/0/ws")
        host = new_host(listen_addrs=[ws_addr])
        
        # Test that host can be started and stopped
        async with host.run():
            addrs = host.get_addrs()
            assert len(addrs) > 0
            # Should have WebSocket addresses
            assert any("/ws" in str(addr) for addr in addrs)

    @pytest.mark.trio
    async def test_tcp_host_creation_and_cleanup(self):
        """Test TCP host can be created and cleaned up properly."""
        tcp_addr = Multiaddr("/ip4/127.0.0.1/tcp/0")
        host = new_host(listen_addrs=[tcp_addr])
        
        # Test that host can be started and stopped
        async with host.run():
            addrs = host.get_addrs() 
            assert len(addrs) > 0
            # Should have TCP addresses
            assert any("/tcp/" in str(addr) for addr in addrs)
            # Should not have WebSocket addresses
            assert not any("/ws" in str(addr) for addr in addrs)


class TestSecurityIntegration:
    """Test that security protocols work with transports."""

    @pytest.mark.trio
    @pytest.mark.skipif(not websocket_available, reason="WebSocket dependencies not available")
    async def test_websocket_with_noise_security(self):
        """Test that WebSocket transport works with Noise security (default)."""
        ws_addr = Multiaddr("/ip4/127.0.0.1/tcp/0/ws")
        
        # Create host with default security (includes Noise)
        host = new_host(listen_addrs=[ws_addr])
        
        async with host.run():
            # Verify that the host has Noise security configured
            swarm = host.get_network()
            upgrader = swarm.upgrader
            
            # Check that Noise protocol is available
            from libp2p.security.noise.transport import PROTOCOL_ID as NOISE_PROTOCOL_ID
            assert NOISE_PROTOCOL_ID in upgrader.secure_transports_by_protocol

    @pytest.mark.trio
    async def test_tcp_with_noise_security(self):
        """Test that TCP transport works with Noise security (default).""" 
        tcp_addr = Multiaddr("/ip4/127.0.0.1/tcp/0")
        
        # Create host with default security (includes Noise)
        host = new_host(listen_addrs=[tcp_addr])
        
        async with host.run():
            # Verify that the host has Noise security configured
            swarm = host.get_network()
            upgrader = swarm.upgrader
            
            # Check that Noise protocol is available
            from libp2p.security.noise.transport import PROTOCOL_ID as NOISE_PROTOCOL_ID
            assert NOISE_PROTOCOL_ID in upgrader.secure_transports_by_protocol


class TestMultiaddrEdgeCases:
    """Test edge cases in multiaddr handling."""

    @pytest.mark.skipif(not websocket_available, reason="WebSocket dependencies not available")
    def test_websocket_with_p2p_suffix(self):
        """Test WebSocket addresses with p2p peer ID suffix."""
        # This should work - the p2p suffix should be handled properly
        ws_addr_with_p2p = Multiaddr("/ip4/127.0.0.1/tcp/8080/ws/p2p/12D3KooWExample")
        
        host = new_host(listen_addrs=[ws_addr_with_p2p])
        assert host is not None
        assert host.get_network().transport.__class__.__name__ == "WebsocketTransport"

    def test_tcp_with_p2p_suffix(self):
        """Test TCP addresses with p2p peer ID suffix."""
        # This should work - the p2p suffix should be handled properly
        tcp_addr_with_p2p = Multiaddr("/ip4/127.0.0.1/tcp/8080/p2p/12D3KooWExample")
        
        host = new_host(listen_addrs=[tcp_addr_with_p2p])
        assert host is not None
        assert host.get_network().transport.__class__.__name__ == "TCP"

    def test_empty_listen_addrs(self):
        """Test that empty listen_addrs defaults to TCP."""
        host = new_host(listen_addrs=None)
        assert host is not None
        assert host.get_network().transport.__class__.__name__ == "TCP"

    def test_multiple_listen_addrs_uses_first(self):
        """Test that multiple listen_addrs uses the first one for transport selection."""
        addrs = [
            Multiaddr("/ip4/127.0.0.1/tcp/8080"),
            Multiaddr("/ip4/127.0.0.1/tcp/8081"),
        ]
        
        host = new_host(listen_addrs=addrs)
        assert host is not None
        assert host.get_network().transport.__class__.__name__ == "TCP"

    @pytest.mark.skipif(not websocket_available, reason="WebSocket dependencies not available")
    def test_multiple_listen_addrs_websocket_first(self):
        """Test that WebSocket is selected when it's the first address."""
        addrs = [
            Multiaddr("/ip4/127.0.0.1/tcp/8080/ws"),
            Multiaddr("/ip4/127.0.0.1/tcp/8081"),
        ]
        
        host = new_host(listen_addrs=addrs)
        assert host is not None
        assert host.get_network().transport.__class__.__name__ == "WebsocketTransport"