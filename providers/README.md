## How to generate a fixture

curl -v https://www.zara.com/es/en/striped-shirt-with-pocket-p02298168.html?v1=500273060 \
  -o /dev/null \
  -w '\nJSONMETA:{"url":"%{url_effective}","status":%{http_code},"time_total":%{time_total},"time_namelookup":%{time_namelookup},"time_connect":%{time_connect},"time_appconnect":%{time_appconnect},"time_starttransfer":%{time_starttransfer},"size":%{size_download},"content_type":"%{content_type}","remote_ip":"%{remote_ip}","remote_port":"%{remote_port}","http_version":"%{http_version}"}\n' \
  2>&1 | node -e '
const fs = require("fs")
const { URL } = require("url")

const input = fs.readFileSync(0, "utf8").split("\n")

const metaLine = input.find(l => l.startsWith("JSONMETA:"))
if (!metaLine) {
  console.error("JSONMETA line not found")
  process.exit(1)
}

const meta = JSON.parse(metaLine.slice(9))

let method = "GET"
const reqHeaders = []
const resHeaders = []

for (const line of input) {
  if (line.startsWith("> ")) {
    const v = line.slice(2)
    if (/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)/.test(v)) {
      method = v.split(" ")[0]
    } else {
      const i = v.indexOf(":")
      if (i > 0) {
        reqHeaders.push({ name: v.slice(0, i).toLowerCase(), value: v.slice(i + 1).trim() })
      }
    }
  }

  if (line.startsWith("< ")) {
    const v = line.slice(2)
    const i = v.indexOf(":")
    if (i > 0) {
      resHeaders.push({ name: v.slice(0, i).toLowerCase(), value: v.slice(i + 1).trim() })
    }
  }
}

const u = new URL(meta.url)

const httpVersion =
  meta.http_version === "2" ? "http/2.0" :
  meta.http_version === "3" ? "h3" :
  meta.http_version ? "http/" + meta.http_version :
  ""

const har = {
  log: {
    version: "1.2",
    creator: { name: "curl+node", version: process.versions.node },
    pages: [{
      id: "page_1",
      title: u.href,
      startedDateTime: new Date().toISOString(),
      pageTimings: { onContentLoad: -1, onLoad: meta.time_total * 1000 }
    }],
    entries: [{
      pageref: "page_1",
      startedDateTime: new Date().toISOString(),
      time: meta.time_total * 1000,
      serverIPAddress: meta.remote_ip || "",
      connection: meta.remote_port || "",
      request: {
        method,
        url: u.href,
        httpVersion,
        headers: [
          { name: ":authority", value: u.host },
          { name: ":method", value: method },
          { name: ":path", value: u.pathname + u.search },
          { name: ":scheme", value: u.protocol.replace(":", "") },
          ...reqHeaders
        ],
        queryString: [...u.searchParams].map(([name, value]) => ({ name, value })),
        cookies: [],
        headersSize: -1,
        bodySize: 0
      },
      response: {
        status: meta.status,
        statusText: "",
        httpVersion,
        headers: resHeaders,
        cookies: [],
        content: { size: meta.size, mimeType: meta.content_type || "" },
        redirectURL: "",
        headersSize: -1,
        bodySize: -1
      }
    }]
  }
}

console.log(JSON.stringify(har, null, 2))
'
