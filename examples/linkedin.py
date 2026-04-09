"""Example using httpx to check LinkedIn for antibot protection."""

import httpx

from is_antibot import is_antibot

url = "https://www.linkedin.com/in/kikobeats/"
headers = {"user-agent": "curl/7.81.0"}

response = httpx.get(url, headers=headers, follow_redirects=True)

result = is_antibot(
    headers=dict(response.headers),
    status_code=response.status_code,
    html=response.text,
    url=str(response.url),
)

print(f"detected: {result.detected}")
print(f"provider: {result.provider}")
print(f"detection: {result.detection}")
