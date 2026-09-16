/**
 * Demonstration endpoints' plumbing: TrustGate and SecureProxy egress.
 *
 * Neither is something an agent framework gives you. They exist so a customer
 * evaluating AgentBox can trigger the two controls that previously had no path
 * at all from inside a running application -- package policy and egress policy
 * -- and see the platform's own verdict, in the platform's own words.
 *
 * Both are deliberately thin: they run the real thing and report what came
 * back. Neither interprets policy, and neither has a "pretend" mode.
 */

import { execFile } from "child_process";
import fs from "fs";
import net from "net";
import path from "path";

// --------------------------------------------------------------- TrustGate

// `pip3` is deliberately absent: TrustGate shims `pip`, not `pip3`, so a
// `pip3 install` would reach the real binary ungoverned.
const MANAGERS = new Set(["npm", "pip"]);

// A package name, an optional npm scope, and an optional version specifier.
// The install runs WITHOUT a shell, so this is defence in depth rather than the
// only thing between a name and a command -- but a name that cannot be a
// package should be refused before TrustGate is asked about it.
//
// Both optional halves are real, not hypothetical: a first version of this
// accepted neither, which refused `@scope/name` and `docopt==0.6.2` -- an
// ordinary scoped npm package and an ordinary pinned pip install. A scope must
// begin with an alphanumeric so `@../evil/x` cannot pass as one.
const PACKAGE_RE =
  /^(?:@[A-Za-z0-9][A-Za-z0-9._-]{0,63}\/)?[A-Za-z0-9][A-Za-z0-9._-]{0,99}(?:[@=<>!~^][A-Za-z0-9._*+!=<>~^-]{0,63})?$/;

// npm needs a project root it can write. /app is an image layer under a
// read-only rootfs, and npm walks UP to the nearest package.json, so without
// one here it targets /app and fails with a misleading ENOENT about a
// platform-specific package. /app/scratch is declared in filesystem_writable.
const INSTALL_ROOT = process.env.DOCBRIEF_INSTALL_ROOT ?? "/app/scratch";

// Substrings meaning TrustGate FAILED rather than DECIDED. They matter because
// they are invisible in the verdict: the daemon wraps every exception as
// "Blocked by KOBIL TrustGate: {exc}", so an infrastructure failure reads word
// for word like a policy block. Check this before trusting a verdict.
const INFRA_FAILURES = [
  "execv",
  "staticx",
  "daemon unavailable",
  "daemon returned no final response",
  "resolution failed",
  "error loading shared library",
  "unsupported resolver tool",
  "connection refused",
];

/**
 * Which decision TrustGate rendered.
 *
 * Keys off the exact prefixes policy.py emits rather than loose keywords:
 * "approval" appears both in a genuine HOLD and in "Blocked by ...: approval
 * request was rejected", so keyword matching cannot tell the two apart.
 */
function verdictOf(output) {
  const lowered = output.toLowerCase();
  if (lowered.includes("blocked by kobil trustgate")) return "block";
  if (lowered.includes("held by kobil trustgate")) return "hold";
  if (lowered.includes("allowed by kobil trustgate")) return "allow";
  return "none";
}

function ensureInstallRoot() {
  fs.mkdirSync(INSTALL_ROOT, { recursive: true });
  const manifest = path.join(INSTALL_ROOT, "package.json");
  if (!fs.existsSync(manifest)) {
    fs.writeFileSync(manifest, '{"name":"agent-scratch","private":true}');
  }
}

/**
 * Run a real, TrustGate-governed install and report the verdict.
 *
 * Invoked as a bare argv, NOT through a shell: a login shell (`sh -lc`)
 * re-initialises PATH from the image profile and drops the shim directory
 * entirely, where a login shell saw no npm at
 * all. This process inherits the container's ENV PATH, which has the shim
 * directory on it, so a bare name resolves to the wrapper exactly as an
 * agent's own call would.
 */
export function installPackage(pkg, manager) {
  const name = String(pkg ?? "").trim();
  const tool = String(manager ?? "").trim().toLowerCase();
  if (!MANAGERS.has(tool)) {
    throw Object.assign(new Error(`manager must be one of ${[...MANAGERS].join(", ")}`), { status: 400 });
  }
  if (!PACKAGE_RE.test(name)) {
    throw Object.assign(new Error("package is not a valid package name"), { status: 400 });
  }

  let cwd;
  if (tool === "npm") {
    ensureInstallRoot();
    cwd = INSTALL_ROOT;
  }

  return new Promise((resolve, reject) => {
    execFile(
      tool,
      ["install", name],
      {
        cwd,
        // 300s: an ALLOWed package proceeds to a real download, and a
        // smaller ceiling gets hit by ordinary ones. A timeout reported as a
        // failure would misattribute a slow network to TrustGate.
        timeout: 300_000,
        maxBuffer: 8 * 1024 * 1024,
      },
      (error, stdout, stderr) => {
        if (error && error.code === "ENOENT") {
          reject(
            Object.assign(
              new Error(`${tool} is not installed in this image, so TrustGate's shim has nothing to wrap`),
              { status: 502 },
            ),
          );
          return;
        }
        if (error && error.killed) {
          reject(Object.assign(new Error(`${tool} install of ${name} did not finish within 300s`), { status: 502 }));
          return;
        }
        const output = `${stdout ?? ""}\n${stderr ?? ""}`.trim();
        const lowered = output.toLowerCase();
        const infra = INFRA_FAILURES.filter((needle) => lowered.includes(needle));
        resolve({
          package: name,
          manager: tool,
          verdict: verdictOf(output),
          exit_code: error?.code ?? 0,
          // Bounded: an ALLOWed install prints a full resolution log, and this
          // is rendered in an admin's browser.
          output: output.slice(-4000),
          // A verdict reached by a broken TrustGate fails CLOSED, which is the
          // safe direction but also the deceptive one -- it looks exactly like
          // a policy block. Name it rather than let it read as enforcement.
          infra_failure: infra.length ? infra : null,
        });
      },
    );
  });
}

// ------------------------------------------------------- SecureProxy egress

const HOST_RE = /^[A-Za-z0-9._-]{1,253}$/;

/**
 * Ask SecureProxy's forward proxy to open a tunnel, and report its answer.
 *
 * A RAW CONNECT, reading the proxy's own status line, rather than an ordinary
 * HTTPS request: a denied CONNECT surfaces to an HTTP client as a generic
 * socket error with the proxy's status discarded, so a probe built on `fetch`
 * reports the same opaque failure whether the destination was refused by
 * policy or the proxy itself was broken. Reading the status line keeps "403
 * Forbidden" distinct from "cannot reach the proxy at all", which is the
 * entire question here.
 */
export function probeEgress(host, port = 443) {
  const target = String(host ?? "").trim();
  if (!HOST_RE.test(target)) {
    throw Object.assign(new Error("host must be a bare hostname, without scheme or path"), { status: 400 });
  }
  const targetPort = Number(port);
  if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
    throw Object.assign(new Error("port must be between 1 and 65535"), { status: 400 });
  }

  const raw = (process.env.HTTPS_PROXY ?? process.env.https_proxy ?? "").trim();
  const base = { host: target, port: targetPort };
  if (!raw) {
    return Promise.resolve({
      ...base,
      proxied: false,
      status: 0,
      reason: "no HTTPS_PROXY is set, so this app has no egress route at all",
    });
  }

  let proxy;
  try {
    proxy = new URL(raw);
  } catch {
    return Promise.resolve({ ...base, proxied: false, status: 0, reason: `unparseable proxy url: ${raw}` });
  }
  const proxyPort = Number(proxy.port);
  if (!proxy.hostname || !proxyPort) {
    return Promise.resolve({ ...base, proxied: false, status: 0, reason: `unparseable proxy url: ${raw}` });
  }

  const lines = [`CONNECT ${target}:${targetPort} HTTP/1.1`, `Host: ${target}:${targetPort}`];
  if (proxy.username) {
    // Spelled exactly `Proxy-Authorization`. Only the exact casing is
    // forwarded into the tunnel by the proxy, and a client library that
    // normalises the header name produces a 407 on every request -- which
    // silently disabled TrustGate's own intel fetches until it was found.
    const token = Buffer.from(
      `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password ?? "")}`,
    ).toString("base64");
    lines.push(`Proxy-Authorization: Basic ${token}`);
  }

  return new Promise((resolve) => {
    let settled = false;
    const finish = (payload) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ ...base, ...payload });
    };

    const socket = net.createConnection({ host: proxy.hostname, port: proxyPort });
    socket.setTimeout(25_000);

    socket.on("connect", () => socket.write(`${lines.join("\r\n")}\r\n\r\n`));
    socket.on("timeout", () =>
      finish({ proxied: true, status: 0, reason: "the proxy did not answer within 25s" }),
    );
    socket.on("error", (error) =>
      finish({
        proxied: false,
        status: 0,
        reason: `cannot reach the proxy at ${proxy.hostname}:${proxyPort} -- ${error.message}`,
      }),
    );
    socket.on("close", () =>
      finish({ proxied: true, status: 0, reason: "the proxy closed the connection without a status line" }),
    );

    let buffer = "";
    socket.on("data", (chunk) => {
      buffer += chunk.toString("latin1");
      if (!buffer.includes("\r\n")) return;
      const statusLine = buffer.split("\r\n", 1)[0];
      const bits = statusLine.split(/\s+/);
      if (bits.length < 2 || !/^\d+$/.test(bits[1])) {
        finish({ proxied: true, status: 0, reason: `unparseable proxy status line: ${statusLine}` });
        return;
      }
      const status = Number(bits[1]);
      finish({
        proxied: true,
        status,
        reason: bits.slice(2).join(" "),
        // 200 means the tunnel opened: this destination is allowed by the
        // app's current egress policy. 403 is the policy refusing it. 407
        // means the credential did not survive, a wiring fault rather than a
        // policy decision.
        allowed: status === 200,
      });
    });
  });
}
