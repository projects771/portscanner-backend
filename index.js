const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const dns = require("dns").promises;
const { scanPorts, getPortsFromPreset, getPortsFromRange, isPrivateOrReserved } = require("./scanner");

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    methods: ["GET", "POST"],
  },
});

app.use(cors({ origin: process.env.CLIENT_URL || "http://localhost:5173" }));
app.use(express.json());

// Rate limit REST endpoints
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { error: "Too many requests. Please wait a minute." },
});
app.use("/api/", limiter);

// DNS lookup endpoint
app.get("/api/resolve/:host", async (req, res) => {
  try {
    const { host } = req.params;
    const addresses = await dns.lookup(host, { all: true });
    res.json({ host, addresses });
  } catch (err) {
    res.status(400).json({ error: `Cannot resolve host: ${err.message}` });
  }
});

// Track active scans per socket to allow cancellation
const activeScans = new Map();

io.on("connection", (socket) => {
  console.log(`Client connected: ${socket.id}`);

  socket.on("start-scan", async (payload) => {
    const { host, mode, preset, rangeStart, rangeEnd } = payload;

    // Validate host
    if (!host || typeof host !== "string" || host.trim().length === 0) {
      socket.emit("scan-error", { message: "Invalid host provided." });
      return;
    }

    const cleanHost = host.trim().toLowerCase();

    // Resolve hostname to IP
    let resolvedIP = cleanHost;
    try {
      const result = await dns.lookup(cleanHost);
      resolvedIP = result.address;
    } catch {
      socket.emit("scan-error", { message: `Cannot resolve hostname: ${cleanHost}` });
      return;
    }

    // 🚨 SECURITY FIX: Prevent scanning internal/private networks (SSRF protection)
    if (isPrivateOrReserved(resolvedIP)) {
      socket.emit("scan-error", { message: "Scanning private or reserved IP ranges is strictly prohibited." });
      return;
    }

    // Build port list
    let ports = [];
    if (mode === "preset" && preset) {
      ports = getPortsFromPreset(preset);
      if (!ports) {
        socket.emit("scan-error", { message: "Invalid preset selected." });
        return;
      }
    } else if (mode === "range") {
      const start = parseInt(rangeStart);
      const end = parseInt(rangeEnd);
      if (isNaN(start) || isNaN(end) || start < 1 || end > 65535 || start > end) {
        socket.emit("scan-error", { message: "Invalid port range. Use 1–65535." });
        return;
      }
      if (end - start > 9999) {
        socket.emit("scan-error", { message: "Range too large. Max 10,000 ports per scan." });
        return;
      }
      ports = getPortsFromRange(start, end);
    } else {
      socket.emit("scan-error", { message: "Invalid scan mode." });
      return;
    }

    // Cancel any existing scan for this socket
    activeScans.set(socket.id, { cancelled: false });
    const scanState = activeScans.get(socket.id);

    socket.emit("scan-started", {
      host: cleanHost,
      resolvedIP,
      totalPorts: ports.length,
      startedAt: new Date().toISOString(),
    });

    const openPorts = [];
    const startTime = Date.now();

    try {
      await scanPorts(cleanHost, ports, 150, (result, completed, total) => {
        if (scanState.cancelled) return;

        if (result.status === "open") {
          openPorts.push(result);
        }

        socket.emit("port-result", {
          ...result,
          completed,
          total,
          progress: Math.round((completed / total) * 100),
        });
      });
    } catch (err) {
      if (!scanState.cancelled) {
        socket.emit("scan-error", { message: "Scan failed unexpectedly." });
      }
      return;
    }

    if (!scanState.cancelled) {
      const duration = ((Date.now() - startTime) / 1000).toFixed(2);
      socket.emit("scan-complete", {
        openPorts,
        totalScanned: ports.length,
        duration,
        finishedAt: new Date().toISOString(),
      });
    }

    activeScans.delete(socket.id);
  });

  socket.on("cancel-scan", () => {
    const state = activeScans.get(socket.id);
    if (state) {
      state.cancelled = true;
      socket.emit("scan-cancelled", { message: "Scan cancelled." });
    }
  });

  socket.on("disconnect", () => {
    const state = activeScans.get(socket.id);
    if (state) state.cancelled = true;
    activeScans.delete(socket.id);
    console.log(`Client disconnected: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 4000;
server.listen(PORT, () => {
  console.log(`🚀 Port Scanner server running on http://localhost:${PORT}`);
});
