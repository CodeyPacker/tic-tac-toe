const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, "data.json");
const sessions = new Map(); // token -> username

function load() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch {
    return { users: {} };
  }
}

function save(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function hash(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function send(res, status, body) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 10000) reject(new Error("too large"));
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(raw || "{}"));
      } catch {
        reject(new Error("bad json"));
      }
    });
  });
}

function currentUser(req) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  return sessions.get(token);
}

function startSession(res, username, user) {
  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, username);
  send(res, 200, { token, username, stats: user.stats });
}

const routes = {
  "POST /api/signup": async (req, res) => {
    const { username, password } = await readBody(req);
    if (typeof username !== "string" || !/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return send(res, 400, { error: "Username must be 3-20 letters, numbers, or _" });
    }
    if (typeof password !== "string" || password.length < 6) {
      return send(res, 400, { error: "Password must be at least 6 characters" });
    }
    const data = load();
    if (data.users[username]) return send(res, 409, { error: "Username taken" });
    const salt = crypto.randomBytes(16).toString("hex");
    const user = { salt, hash: hash(password, salt), stats: { wins: 0, losses: 0, draws: 0 } };
    data.users[username] = user;
    save(data);
    startSession(res, username, user);
  },

  "POST /api/login": async (req, res) => {
    const { username, password } = await readBody(req);
    const user = load().users[username];
    const ok =
      user &&
      typeof password === "string" &&
      crypto.timingSafeEqual(Buffer.from(hash(password, user.salt), "hex"), Buffer.from(user.hash, "hex"));
    if (!ok) return send(res, 401, { error: "Wrong username or password" });
    startSession(res, username, user);
  },

  "POST /api/logout": async (req, res) => {
    sessions.delete((req.headers.authorization || "").replace("Bearer ", ""));
    send(res, 200, {});
  },

  "GET /api/me": async (req, res) => {
    const username = currentUser(req);
    if (!username) return send(res, 401, { error: "Not logged in" });
    send(res, 200, { username, stats: load().users[username].stats });
  },

  // The logged-in player is always X. result is "win", "loss", or "draw".
  "POST /api/result": async (req, res) => {
    const username = currentUser(req);
    if (!username) return send(res, 401, { error: "Not logged in" });
    const { result } = await readBody(req);
    const key = { win: "wins", loss: "losses", draw: "draws" }[result];
    if (!key) return send(res, 400, { error: "Bad result" });
    const data = load();
    data.users[username].stats[key]++;
    save(data);
    send(res, 200, { stats: data.users[username].stats });
  },
};

http
  .createServer(async (req, res) => {
    const route = routes[`${req.method} ${req.url}`];
    try {
      if (route) return await route(req, res);
      if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
        res.writeHead(200, { "Content-Type": "text/html" });
        return res.end(fs.readFileSync(path.join(__dirname, "index.html")));
      }
      send(res, 404, { error: "Not found" });
    } catch (err) {
      send(res, 400, { error: err.message });
    }
  })
  .listen(PORT, () => console.log(`http://localhost:${PORT}`));
