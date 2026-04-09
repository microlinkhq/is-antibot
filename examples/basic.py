"""Basic example using urllib to check LinkedIn for antibot protection."""

from urllib.request import Request, urlopen

from is_antibot import is_antibot

url = "https://www.linkedin.com/in/kikobeats/"
req = Request(url)
response = urlopen(req)

result = is_antibot(
    headers=dict(response.headers),
    status_code=response.status,
    html=response.read().decode(),
    url=response.url,
)

if result.detected:
    print(f"Blocked by {result.provider} (via {result.detection})")
