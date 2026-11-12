
import os
import json
import requests

BASE = "http://localhost:4000"
KEY = os.environ["LITELLM_MASTER_KEY"]

SERVER_ID = "af309339d7e8fdaf56cd71d985b895b8"
CLOUD_ID = "b97c2ba3-5e63-4330-a2d3-f9b464ee5736"

headers = {
    "Authorization": f"Bearer {KEY}",
    "Content-Type": "application/json",
}

payload = {
    "server_id": SERVER_ID,
    "name": "getConfluenceContent",
    "arguments": {
        "cloudId": CLOUD_ID,
        "content_id": "262377",
        "content_format": "markdown",
        "detail": "full"
    }
}

response = requests.post(
    f"{BASE}/mcp-rest/tools/call",
    headers=headers,
    json=payload,
    timeout=60,
)

print("HTTP status:", response.status_code)

result = response.json()
print("MCP error:", result.get("isError", False))

for item in result.get("content", []):
    if item.get("type") == "text":
        print("\nConfluence page response:")
        print(item.get("text", "")[:8000])