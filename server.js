const express = require("express");
const fs = require("fs");
const app = express();
app.use(express.json());

const DB = "keys.json";
const ADMIN = process.env.ADMIN_SECRET;
if (!ADMIN) { console.error("ตั้ง ADMIN_SECRET ก่อน"); process.exit(1); }

let keys = fs.existsSync(DB) ? JSON.parse(fs.readFileSync(DB)) : {};
const save = () => fs.writeFileSync(DB, JSON.stringify(keys, null, 2));
const now = () => Math.floor(Date.now() / 1000);

const hits = new Map();
app.use((req, res, next) => {
  const ip = req.headers["x-forwarded-for"] || req.ip;
  const t = now(), h = (hits.get(ip) || []).filter(x => t - x < 60);
  h.push(t); hits.set(ip, h);
  if (h.length > 15) return res.status(429).json({ ok: false, msg: "Too many requests" });
  next();
});

app.post("/verify", (req, res) => {
  const { key, userId } = req.body || {};
  if (typeof key !== "string" || !userId) return res.json({ ok: false, msg: "Bad request" });
  if (key === ADMIN) return res.json({ ok: true, role: "admin", type: "Admin", remaining: -1 });
  const k = keys[key];
  if (!k) return res.json({ ok: false, msg: "Invalid or unregistered key!" });
  if (k.boundUser && k.boundUser !== userId)
    return res.json({ ok: false, msg: "Key is bound to another user!" });
  if (!k.boundUser) { k.boundUser = userId; k.boundName = req.body.user; }
  if (!k.start) k.start = now();
  save();
  if (k.duration === -1) return res.json({ ok: true, type: k.type, remaining: -1 });
  const remaining = k.start + k.duration - now();
  if (remaining <= 0) return res.json({ ok: false, msg: "This key has expired!" });
  res.json({ ok: true, type: k.type, remaining });
});

const isAdmin = (req, res, next) =>
  req.headers["x-admin"] === ADMIN ? next() : res.status(403).json({ ok: false });

app.post("/admin/create", isAdmin, (req, res) => {
  const { name, duration, type } = req.body || {};
  if (!name || typeof duration !== "number") return res.json({ ok: false });
  keys[name] = { duration, type, boundUser: null, boundName: null, start: null };
  save(); res.json({ ok: true });
});

app.post("/admin/delete", isAdmin, (req, res) => {
  delete keys[req.body.name]; save(); res.json({ ok: true });
});

app.post("/admin/reset", isAdmin, (req, res) => {
  const k = keys[req.body.name];
  if (k) { k.boundUser = null; k.boundName = null; save(); }
  res.json({ ok: true });
});

app.post("/admin/list", isAdmin, (req, res) => {
  res.json({ ok: true, list: Object.entries(keys).map(([name, k]) => ({
    name, type: k.type, boundName: k.boundName, boundUser: k.boundUser })) });
});

app.listen(process.env.PORT || 3000, () => console.log("key server up"));
