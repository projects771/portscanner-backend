const net = require("net");

// Well-known service names for common ports
const SERVICE_MAP = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  25: "SMTP",
  53: "DNS",
  80: "HTTP",
  110: "POP3",
  135: "RPC",
  139: "NetBIOS",
  143: "IMAP",
  443: "HTTPS",
  445: "SMB",
  465: "SMTPS",
  587: "SMTP (TLS)",
  993: "IMAPS",
  995: "POP3S",
  1433: "MSSQL",
  1521: "Oracle DB",
  2181: "Zookeeper",
  3000: "Dev Server",
  3306: "MySQL",
  3389: "RDP",
  4000: "Dev Server",
  5000: "Dev Server",
  5432: "PostgreSQL",
  5900: "VNC",
  6379: "Redis",
  6443: "Kubernetes",
  7000: "Cassandra",
  8000: "HTTP Alt",
  8080: "HTTP Proxy",
  8443: "HTTPS Alt",
  8888: "Jupyter",
  9000: "SonarQube",
  9090: "Prometheus",
  9200: "Elasticsearch",
  27017: "MongoDB",
  27018: "MongoDB Shard",
};

// Preset port groups
const PORT_PRESETS = {
  top20: [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080],
  top100: [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 514, 587,
    631, 993, 995, 1025, 1080, 1194, 1433, 1521, 1723, 2049, 2181, 2375, 2376,
    3000, 3306, 3389, 4000, 4369, 5000, 5432, 5900, 5938, 6379, 6443, 6881,
    7000, 7001, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300,
    10000, 11211, 15672, 16379, 27017, 27018, 28015, 50000,
    // Fill to 100
    81, 82, 83, 84, 85, 88, 89, 90, 99, 100,
    106, 119, 125, 161, 162, 163, 164, 179, 199, 211,
    222, 254, 255, 256, 259, 264, 280, 301, 306, 311,
    340, 366, 389, 406, 407, 416, 417, 425, 427, 444,
  ],
  web: [80, 443, 8000, 8001, 8008, 8080, 8081, 8443, 8888, 9000, 9001, 3000, 4000, 5000],
  database: [1433, 1521, 3306, 5432, 6379, 9200, 27017, 27018, 28015, 11211, 5984, 7474],
  remote: [22, 23, 3389, 5900, 5901, 5902, 5903, 2222, 8022],
};

function scanPort(host, port, timeout = 2000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const startTime = Date.now();

    socket.setTimeout(timeout);

    socket.connect(port, host, () => {
      const responseTime = Date.now() - startTime;
      socket.destroy();
      resolve({
        port,
        status: "open",
        service: SERVICE_MAP[port] || "Unknown",
        responseTime,
      });
    });

    socket.on("error", (err) => {
      const responseTime = Date.now() - startTime;
      socket.destroy();
      resolve({
        port,
        status: err.code === "ECONNREFUSED" ? "closed" : "filtered",
        service: SERVICE_MAP[port] || "Unknown",
        responseTime,
      });
    });

    socket.on("timeout", () => {
      const responseTime = Date.now() - startTime;
      socket.destroy();
      resolve({
        port,
        status: "filtered",
        service: SERVICE_MAP[port] || "Unknown",
        responseTime,
      });
    });
  });
}

async function scanPorts(host, ports, concurrency = 100, onResult) {
  let index = 0;
  let completed = 0;
  const total = ports.length;

  async function worker() {
    while (index < total) {
      const port = ports[index++];
      const result = await scanPort(host, port);
      completed++;
      onResult(result, completed, total);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, total) }, worker);
  await Promise.all(workers);
}

function getPortsFromPreset(preset) {
  return PORT_PRESETS[preset] || null;
}

function getPortsFromRange(start, end) {
  const ports = [];
  for (let i = start; i <= end; i++) ports.push(i);
  return ports;
}

// Block scanning private/reserved IP ranges
function isPrivateOrReserved(host) {
  const privateRanges = [
    /^127\./,                 // Block loopback (127.0.0.0/8)
    /^10\./,                  // Block 10.0.0.0/8
    /^172\.(1[6-9]|2\d|3[01])\./, // Block 172.16.0.0/12
    /^192\.168\./,            // Block 192.168.0.0/16
    /^169\.254\./,            // Block 169.254.0.0/16 (Link-local)
    /^::1$/,                  // Block IPv6 loopback
    /^fc00:/,                 // Block IPv6 Unique Local Addresses
    /^fe80:/,                 // Block IPv6 Link-Local
  ];

  return privateRanges.some((re) => re.test(host));
}

module.exports = { scanPorts, getPortsFromPreset, getPortsFromRange, isPrivateOrReserved, PORT_PRESETS };
