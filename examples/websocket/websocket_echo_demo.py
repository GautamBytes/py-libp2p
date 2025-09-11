#!/usr/bin/env python3
"""
WebSocket Echo Demo with Security Support

This demo shows how to use py-libp2p's WebSocket transport with different security protocols.
It demonstrates IPv4, IPv6, and DNS address support with Noise encryption.
"""

import argparse
import logging
import signal
import sys
import traceback

import multiaddr
import trio

from libp2p import new_host
from libp2p.custom_types import TProtocol
from libp2p.peer.peerinfo import info_from_p2p_addr

# Enable detailed logging for debugging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Echo protocol
ECHO_PROTOCOL_ID = TProtocol("/echo/1.0.0")


async def echo_handler(stream):
    """Echo handler that responds to incoming messages."""
    try:
        while True:
            data = await stream.read(1024)
            if not data:
                break
            
            message = data.decode("utf-8", errors="replace")
            logger.info(f"📥 Received: {message}")
            
            # Echo back the message
            response = f"Echo: {message}"
            await stream.write(response.encode("utf-8"))
            logger.info(f"📤 Sent: {response}")
            
    except Exception as e:
        logger.error(f"Echo handler error: {e}")
    finally:
        await stream.close()


async def run_server(listen_addr_str: str):
    """Run a WebSocket server."""
    listen_addr = multiaddr.Multiaddr(listen_addr_str)
    logger.info(f"🌐 Starting WebSocket server on {listen_addr}")
    
    try:
        # Create host with WebSocket support
        host = new_host(listen_addrs=[listen_addr])
        
        # Set up echo handler
        host.set_stream_handler(ECHO_PROTOCOL_ID, echo_handler)
        
        async with host.run():
            # Get the actual listening addresses
            addrs = host.get_addrs()
            if not addrs:
                logger.error("❌ No listening addresses found")
                return
                
            server_addr = str(addrs[0])
            # Replace 0.0.0.0 with 127.0.0.1 for client connections  
            client_addr = server_addr.replace("/ip4/0.0.0.0/", "/ip4/127.0.0.1/")
            
            logger.info("🎉 WebSocket Server Started Successfully!")
            logger.info("=" * 60)
            logger.info(f"📍 Server Address: {client_addr}")
            logger.info(f"🔧 Protocol: {ECHO_PROTOCOL_ID}")
            logger.info("🚀 Transport: WebSocket (/ws) with Noise encryption")
            logger.info("🔒 Security: Noise protocol enabled by default")
            logger.info("")
            logger.info("📋 To test the connection, run:")
            logger.info(f"   python websocket_echo_demo.py -d {client_addr}")
            logger.info("")
            logger.info("⏳ Waiting for incoming WebSocket connections...")
            logger.info("-" * 60)
            
            # Keep running until interrupted
            await trio.sleep_forever()
            
    except Exception as e:
        logger.error(f"❌ Server error: {e}")
        traceback.print_exc()


async def run_client(target_addr_str: str):
    """Run a WebSocket client."""
    logger.info(f"🔌 Starting WebSocket client, connecting to {target_addr_str}")
    
    try:
        # Create client host with ephemeral port
        client_addr = multiaddr.Multiaddr("/ip4/0.0.0.0/tcp/0/ws")
        host = new_host(listen_addrs=[client_addr])
        
        async with host.run():
            # Parse target address
            target_addr = multiaddr.Multiaddr(target_addr_str)
            peer_info = info_from_p2p_addr(target_addr)
            
            logger.info("🔗 WebSocket Client Details:")
            logger.info("=" * 40)
            logger.info(f"🎯 Target Peer: {peer_info.peer_id}")
            logger.info(f"📍 Target Address: {target_addr_str}")
            logger.info("🔒 Security: Noise protocol enabled")
            logger.info("")
            
            # Connect to the server
            logger.info("🔗 Connecting to WebSocket server...")
            await host.connect(peer_info)
            logger.info("✅ Successfully connected!")
            
            # Create a stream for the echo protocol
            stream = await host.new_stream(peer_info.peer_id, [ECHO_PROTOCOL_ID])
            logger.info("✅ Echo protocol stream established!")
            
            # Send test messages
            test_messages = [
                "Hello WebSocket with Security!",
                "This is using Noise encryption 🔒",
                "IPv6 and DNS addresses are supported too! 🌐",
                "WebSocket transport is working perfectly! 🎉"
            ]
            
            logger.info("🚀 Starting Echo Protocol Test...")
            logger.info("-" * 40)
            
            for i, message in enumerate(test_messages, 1):
                logger.info(f"📤 Sending message {i}: {message}")
                await stream.write(message.encode("utf-8"))
                
                # Read response
                logger.info("⏳ Waiting for server response...")
                response = await stream.read(1024)
                response_text = response.decode("utf-8")
                logger.info(f"📥 Received response: {response_text}")
                logger.info("")
                
                # Small delay between messages
                await trio.sleep(0.5)
            
            await stream.close()
            
            logger.info("-" * 40)
            logger.info("🎉 All echo tests completed successfully!")
            logger.info("✅ WebSocket transport with Noise security is working!")
            
    except Exception as e:
        logger.error(f"❌ Client error: {e}")
        traceback.print_exc()


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="""
WebSocket Echo Demo with Security Support

This demo showcases py-libp2p's WebSocket transport with Noise encryption.

Examples:
  # Start server on IPv4
  python websocket_echo_demo.py -l /ip4/0.0.0.0/tcp/8080/ws

  # Start server on IPv6  
  python websocket_echo_demo.py -l /ip6/::/tcp/8080/ws

  # Connect to server
  python websocket_echo_demo.py -d /ip4/127.0.0.1/tcp/8080/ws/p2p/<PEER_ID>
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-l", "--listen",
        help="Listen on the specified WebSocket multiaddr (server mode)"
    )
    group.add_argument(
        "-d", "--dial", 
        help="Dial the specified WebSocket multiaddr (client mode)"
    )
    
    args = parser.parse_args()
    
    # Handle Ctrl+C gracefully
    def signal_handler(signum, frame):
        logger.info("\n👋 Shutting down gracefully...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        if args.listen:
            logger.info("🌟 WebSocket Server Mode")
            logger.info("=" * 30)
            trio.run(run_server, args.listen)
        else:
            logger.info("🌟 WebSocket Client Mode") 
            logger.info("=" * 30)
            trio.run(run_client, args.dial)
            
    except KeyboardInterrupt:
        logger.info("👋 Demo interrupted by user")
    except Exception as e:
        logger.error(f"❌ Demo failed: {e}")
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())