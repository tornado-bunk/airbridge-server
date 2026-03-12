import asyncio
import json
import logging
import websockets

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

WS_URL = "ws://localhost:8080/ws"
PAIRING_ID = "python-test-999"

async def simulate_mac():
    logging.info("[MAC] Connecting to server...")
    async with websockets.connect(WS_URL) as ws:
        # 1. Register
        reg_msg = {
            "action": "register",
            "role": "mac",
            "pairingId": PAIRING_ID,
            "secret": "sim-secret-42",
            "localIp": "192.168.1.55",
            "port": 4040
        }
        await ws.send(json.dumps(reg_msg))
        logging.info("[MAC] Registered IP: 192.168.1.55")

        # Keep connection open and wait for Relay
        while True:
            response = await ws.recv()
            if isinstance(response, bytes):
                logging.info(f"[MAC] Received Binary Relay Payload: {response}")
                # Echo back slightly modified payload
                await ws.send(b"MAC_ACK:" + response)
            else:
                logging.info(f"[MAC] Received Text Message: {response}")

async def simulate_android():
    # Wait a bit to ensure Mac registers first
    await asyncio.sleep(1)
    
    logging.info("[ANDROID] Connecting to server...")
    async with websockets.connect(WS_URL) as ws:
        # 1. Query Mac IP
        query_msg = {
            "action": "query",
            "role": "android",
            "pairingId": PAIRING_ID,
            "secret": "sim-secret-42"
        }
        await ws.send(json.dumps(query_msg))
        
        info_resp = await ws.recv()
        logging.info(f"[ANDROID] Received Mac Info: {info_resp}")

        # 2. Request Relay
        relay_req = {
            "action": "request_relay",
            "role": "android",
            "pairingId": PAIRING_ID,
            "secret": "sim-secret-42"
        }
        logging.info("[ANDROID] Requesting Relay Tunnel...")
        await ws.send(json.dumps(relay_req))

        relay_ready = await ws.recv()
        logging.info(f"[ANDROID] Tunnel Status: {relay_ready}")

        # 3. Send Fake E2EE Payload
        fake_payload = b"HELLO_FROM_ANDROID_E2EE"
        logging.info(f"[ANDROID] Sending encrypted payload: {fake_payload}")
        await ws.send(fake_payload)

        # 4. Wait for Mac's answer
        mac_ack = await ws.recv()
        logging.info(f"[ANDROID] Received Relay Answer from Mac: {mac_ack}")

async def main():
    mac_task = asyncio.create_task(simulate_mac())
    android_task = asyncio.create_task(simulate_android())
    
    # Run the simulation for 3 seconds then stop
    await asyncio.sleep(3)
    mac_task.cancel()
    android_task.cancel()

if __name__ == "__main__":
    asyncio.run(main())
