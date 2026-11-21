import { connect } from "cloudflare:sockets";
import {
  loadX509FromPem,
  type Logger,
  makeTLSClient,
  MOZILLA_ROOT_CA_LIST,
  setCryptoImplementation,
  verifyCertificateChain,
  type X509Certificate,
} from "@reclaimprotocol/tls";
import { webcryptoCrypto } from "@reclaimprotocol/tls/webcrypto";

setCryptoImplementation(webcryptoCrypto);

const SILENT_TLS_LOGGER: Logger = {
  info: () => {},
  debug: () => {},
  trace: () => {},
  warn: () => {},
  error: () => {},
};

let cachedMozillaRootCAs: X509Certificate[] | null = null;
function getMozillaRootCAs(): X509Certificate[] {
  if (!cachedMozillaRootCAs) {
    cachedMozillaRootCAs = MOZILLA_ROOT_CA_LIST.map((pem) => loadX509FromPem(pem));
  }
  return cachedMozillaRootCAs;
}

function isIpLiteral(host: string): boolean {
  const clean = host.replace(/^\[|\]$/g, "");
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(clean) || clean.includes(":");
}

async function verifyIpCertificateChain(
  certificates: X509Certificate[],
  targetIp: string
): Promise<void> {
  if (certificates.length === 0) {
    throw new Error("目标服务器未返回 TLS 证书");
  }
  const leaf = certificates[0];
  const cleanIp = targetIp.replace(/^\[|\]$/g, "").toLowerCase();

  const sanExt = (
    leaf.internal as {
      extensions?: Array<{
        type?: string;
        names?: { items?: Array<{ type?: string; value?: string }> };
      }>;
    }
  )?.extensions?.find((e) => e.type === "2.5.29.17");
  const ipSans = (sanExt?.names?.items || [])
    .filter((item) => item.type === "ip" && typeof item.value === "string")
    .map((item) => item.value!.replace(/^\[|\]$/g, "").toLowerCase());
  const cnValues = leaf.getSubjectField("CN");

  const ipMatched =
    ipSans.some((ip) => ip === cleanIp) ||
    cnValues.some((cn) => cn.trim().toLowerCase() === cleanIp);
  if (!ipMatched) {
    throw new Error(`目标服务器 TLS 证书未包含 IP ${cleanIp}`);
  }

  const chainHost = cnValues[0] || leaf.getAlternativeDNSNames()[0];
  if (chainHost) {
    await verifyCertificateChain(certificates, chainHost, SILENT_TLS_LOGGER);
    return;
  }

  // Fallback for IP-SAN-only certificates without CN or DNS SAN
  const roots = getMozillaRootCAs();
  const remaining = certificates.slice(1);
  let cert = leaf;
  for (let i = 0; i < 10; i++) {
    if (!cert.isWithinValidity()) {
      throw new Error(`目标服务器 TLS 证书已过期或尚未生效 (index=${i})`);
    }
    const rootIssuer = roots.find((r) => r.isIssuer(cert));
    const issuer =
      rootIssuer ||
      (() => {
        const idx = remaining.findIndex((c) => c.isIssuer(cert));
        if (idx === -1) return undefined;
        return remaining.splice(idx, 1)[0];
      })();
    if (!issuer) {
      throw new Error(`目标服务器 TLS 证书链不完整，缺少签发者 (index=${i})`);
    }
    if (!issuer.isWithinValidity()) {
      throw new Error(`签发者证书已过期或尚未生效 (index=${i})`);
    }
    if (!(await issuer.verifyIssued(cert))) {
      throw new Error(`目标服务器 TLS 证书链签名校验失败 (index=${i})`);
    }
    if (rootIssuer) {
      return;
    }
    cert = issuer;
  }
  throw new Error("目标服务器 TLS 证书链过长");
}

interface UserspaceTlsTunnel {
  readable: ReadableStream<Uint8Array>;
  write: (data: Uint8Array) => Promise<void>;
  close: () => Promise<void>;
}

async function openUserspaceTlsTunnel(
  rawSocket: Socket,
  targetHost: string
): Promise<UserspaceTlsTunnel> {
  const rawWriter = rawSocket.writable.getWriter();
  const rawReader = rawSocket.readable.getReader();

  let streamController: ReadableStreamDefaultController<Uint8Array> | null = null;
  let streamClosed = false;
  let handshakeCompleted = false;
  let handshakeSettled = false;
  let certCheckPromise: Promise<void> | null = null;

  let resolveHandshake!: () => void;
  let rejectHandshake!: (err: Error) => void;
  const handshakePromise = new Promise<void>((resolve, reject) => {
    resolveHandshake = resolve;
    rejectHandshake = reject;
  });

  const closeStream = () => {
    if (!streamClosed && streamController) {
      streamClosed = true;
      try {
        streamController.close();
      } catch {
        // ignore already closed stream
      }
    }
  };

  const failStream = (err: Error) => {
    if (!streamClosed && streamController) {
      streamClosed = true;
      try {
        streamController.error(err);
      } catch {
        // ignore already closed/errored stream
      }
    }
  };

  const settleHandshakeError = (err: unknown) => {
    const error = err instanceof Error ? err : new Error(String(err));
    if (!handshakeSettled) {
      handshakeSettled = true;
      rejectHandshake(error);
    }
    failStream(error);
  };

  const plaintextReadable = new ReadableStream<Uint8Array>({
    start(controller) {
      streamController = controller;
    },
    cancel() {
      streamClosed = true;
    },
  });

  const ipTarget = isIpLiteral(targetHost);
  const tlsClient = makeTLSClient({
    host: targetHost,
    verifyServerCertificate: !ipTarget,
    applicationLayerProtocols: ["http/1.1"],
    logger: SILENT_TLS_LOGGER,
    async write({ header, content }) {
      const payload = concatBytes([header, content]);
      await rawWriter.write(payload);
    },
    onRecvCertificates({ certificates }) {
      if (ipTarget) {
        certCheckPromise = verifyIpCertificateChain(certificates, targetHost);
      }
    },
    onHandshake() {
      (async () => {
        if (ipTarget) {
          if (!certCheckPromise) {
            throw new Error("目标服务器未返回 TLS 证书");
          }
          await certCheckPromise;
        }
        handshakeCompleted = true;
        if (!handshakeSettled) {
          handshakeSettled = true;
          resolveHandshake();
        }
      })().catch((err) => {
        settleHandshakeError(err);
      });
    },
    onApplicationData(plaintext) {
      if (!streamClosed && streamController) {
        try {
          streamController.enqueue(new Uint8Array(plaintext));
        } catch {
          // ignore if consumer canceled
        }
      }
    },
    onTlsEnd(err) {
      if (err) {
        settleHandshakeError(err);
      } else if (!handshakeCompleted) {
        settleHandshakeError(new Error("TLS 握手被目标服务器关闭"));
      } else {
        closeStream();
      }
    },
  });

  const pumpPromise = (async () => {
    try {
      while (true) {
        const { value, done } = await rawReader.read();
        if (done) {
          if (!handshakeCompleted) {
            settleHandshakeError(new Error("TLS 握手期间连接被提前关闭"));
          } else {
            closeStream();
          }
          break;
        }
        if (value && value.length > 0) {
          await tlsClient.handleReceivedBytes(value);
        }
      }
    } catch (err) {
      settleHandshakeError(err);
    } finally {
      try {
        rawReader.releaseLock();
      } catch {
        // ignore
      }
    }
  })();

  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    closeStream();
    await tlsClient.end().catch(() => {});
    try {
      await rawReader.cancel().catch(() => {});
    } catch {
      // ignore if lock already released
    }
    try {
      rawWriter.releaseLock();
    } catch {
      // ignore
    }
    await pumpPromise.catch(() => {});
  };

  try {
    await tlsClient.startHandshake();
    await handshakePromise;
  } catch (err) {
    await close();
    throw err;
  }

  return {
    readable: plaintextReadable,
    write: (data: Uint8Array) => tlsClient.write(data),
    close,
  };
}

export interface ParsedProxyConfig {
  scheme: "socks5" | "http";
  host: string;
  port: number;
  username: string;
  password: string;
}

export interface UpstreamHttpResponse {
  status: number;
  headers: Record<string, string>;
  bodyText: string;
}

/**
 * Parses standard proxy URLs (`socks5://user:pass@host:port`, `socks5h://...`, `http://...`)
 * as well as common scraper proxy shorthands (`host:port:user:pass` or `host:port`).
 */
export function parseProxyConfig(rawInput: string): ParsedProxyConfig {
  const input = rawInput.trim();
  if (!input) {
    throw new Error("代理地址为空");
  }

  if (/^(socks5h?|socks|https?):\/\//i.test(input)) {
    let parsed: URL;
    try {
      parsed = new URL(input);
    } catch {
      throw new Error("代理 URL 格式不合法，示例: socks5://user:pass@host:port");
    }
    const proto = parsed.protocol.replace(":", "").toLowerCase();
    const scheme: "socks5" | "http" = proto.startsWith("http") ? "http" : "socks5";
    const host = parsed.hostname;
    const port = Number(parsed.port);
    if (!host || !port || Number.isNaN(port)) {
      throw new Error("代理地址缺少有效的端号 (host:port)");
    }
    return {
      scheme,
      host,
      port,
      username: parsed.username ? decodeURIComponent(parsed.username) : "",
      password: parsed.password ? decodeURIComponent(parsed.password) : "",
    };
  }

  // Scraper proxy shorthand: host:port:user:pass or host:port
  const parts = input.split(":");
  if (parts.length >= 2) {
    const host = parts[0].trim();
    const port = Number(parts[1].trim());
    if (host && port && !Number.isNaN(port)) {
      const username = parts.length >= 3 ? parts[2].trim() : "";
      const password = parts.length >= 4 ? parts.slice(3).join(":").trim() : "";
      return { scheme: "socks5", host, port, username, password };
    }
  }

  throw new Error("无法识别代理格式，请使用 socks5://user:pass@host:port 或 host:port:user:pass");
}

function concatBytes(chunks: Uint8Array[], totalLen?: number): Uint8Array {
  const len = totalLen ?? chunks.reduce((acc, c) => acc + c.length, 0);
  const out = new Uint8Array(len);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function findDoubleCrlf(buf: Uint8Array): number {
  for (let i = 0; i <= buf.length - 4; i++) {
    if (buf[i] === 13 && buf[i + 1] === 10 && buf[i + 2] === 13 && buf[i + 3] === 10) {
      return i;
    }
  }
  return -1;
}

class StreamBufferReader {
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private buffer: Uint8Array = new Uint8Array(0);

  constructor(readable: ReadableStream<Uint8Array>) {
    this.reader = readable.getReader();
  }

  async readExact(n: number): Promise<Uint8Array> {
    while (this.buffer.length < n) {
      const { value, done } = await this.reader.read();
      if (done || !value) {
        throw new Error("代理握手连接被提前关闭");
      }
      this.buffer = concatBytes([this.buffer, value]);
    }
    const result = this.buffer.slice(0, n);
    this.buffer = this.buffer.slice(n);
    return result;
  }

  async readUntilHeaderEnd(maxBytes = 32768): Promise<{ headerBytes: Uint8Array; rest: Uint8Array }> {
    while (true) {
      const idx = findDoubleCrlf(this.buffer);
      if (idx !== -1) {
        const headerBytes = this.buffer.slice(0, idx);
        const rest = this.buffer.slice(idx + 4);
        this.buffer = new Uint8Array(0);
        return { headerBytes, rest };
      }
      if (this.buffer.length > maxBytes) {
        throw new Error("响应头超过大小限制");
      }
      const { value, done } = await this.reader.read();
      if (done || !value) {
        throw new Error("读取 HTTP 响应头时连接中断");
      }
      this.buffer = concatBytes([this.buffer, value]);
    }
  }

  async readRemainingBody(
    initialRest: Uint8Array,
    contentLength: number | null,
    isChunked: boolean,
    maxBytes = 8 * 1024 * 1024
  ): Promise<Uint8Array> {
    if (isChunked) {
      let rawBuf = initialRest;
      const decodedChunks: Uint8Array[] = [];
      let totalDecoded = 0;

      while (true) {
        // Find CRLF of chunk size line
        let lineEnd = -1;
        for (let i = 0; i <= rawBuf.length - 2; i++) {
          if (rawBuf[i] === 13 && rawBuf[i + 1] === 10) {
            lineEnd = i;
            break;
          }
        }
        if (lineEnd === -1) {
          const { value, done } = await this.reader.read();
          if (done || !value) break;
          rawBuf = concatBytes([rawBuf, value]);
          continue;
        }

        const sizeLine = new TextDecoder().decode(rawBuf.slice(0, lineEnd)).split(";")[0].trim();
        const chunkSize = parseInt(sizeLine, 16);
        if (Number.isNaN(chunkSize)) {
          throw new Error("Chunked 响应编码解析失败");
        }
        if (chunkSize === 0) {
          break;
        }
        if (totalDecoded + chunkSize > maxBytes) {
          throw new Error("订阅响应体积超出上限 (8MB)");
        }

        const needed = lineEnd + 2 + chunkSize + 2;
        while (rawBuf.length < needed) {
          const { value, done } = await this.reader.read();
          if (done || !value) break;
          rawBuf = concatBytes([rawBuf, value]);
        }

        const chunkData = rawBuf.slice(lineEnd + 2, lineEnd + 2 + chunkSize);
        decodedChunks.push(chunkData);
        totalDecoded += chunkData.length;
        rawBuf = rawBuf.slice(Math.min(rawBuf.length, needed));
      }

      return concatBytes(decodedChunks, totalDecoded);
    }

    const chunks: Uint8Array[] = initialRest.length > 0 ? [initialRest] : [];
    let total = initialRest.length;

    while (contentLength === null || total < contentLength) {
      const { value, done } = await this.reader.read();
      if (done || !value) break;
      chunks.push(value);
      total += value.length;
      if (total > maxBytes) {
        throw new Error("订阅响应体积超出上限 (8MB)");
      }
    }

    const combined = concatBytes(chunks, total);
    return contentLength !== null ? combined.slice(0, contentLength) : combined;
  }

  release(): void {
    this.reader.releaseLock();
  }
}

async function performSocks5Handshake(
  socket: Socket,
  proxy: ParsedProxyConfig,
  targetHost: string,
  targetPort: number
): Promise<void> {
  const enc = new TextEncoder();
  const writer = socket.writable.getWriter();
  const reader = new StreamBufferReader(socket.readable);

  try {
    // 1. Greeting: offer NO-AUTH (0x00) and optionally USERNAME/PASSWORD (0x02)
    if (proxy.username) {
      await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
    } else {
      await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
    }

    const methodResp = await reader.readExact(2);
    if (methodResp[0] !== 0x05 || methodResp[1] === 0xff) {
      throw new Error("SOCKS5 代理握手被拒绝 (不支持的认证方式)");
    }

    // 2. RFC 1929 Username/Password sub-negotiation
    if (methodResp[1] === 0x02) {
      const uBytes = enc.encode(proxy.username);
      const pBytes = enc.encode(proxy.password);
      if (uBytes.length > 255 || pBytes.length > 255) {
        throw new Error("SOCKS5 账号密码长度超出协议上限");
      }
      const authReq = new Uint8Array(3 + uBytes.length + pBytes.length);
      authReq[0] = 0x01;
      authReq[1] = uBytes.length;
      authReq.set(uBytes, 2);
      authReq[2 + uBytes.length] = pBytes.length;
      authReq.set(pBytes, 3 + uBytes.length);
      await writer.write(authReq);

      const authResp = await reader.readExact(2);
      if (authResp[1] !== 0x00) {
        throw new Error("SOCKS5 代理账号或密码鉴权失败");
      }
    } else if (methodResp[1] !== 0x00) {
      throw new Error(`SOCKS5 返回未知认证方法 (0x${methodResp[1].toString(16)})`);
    }

    // 3. CONNECT command (ATYP=0x01 for IPv4 literal, ATYP=0x03 for Domain Name -> remote DNS)
    const ipv4Match = targetHost.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    let connReq: Uint8Array;
    if (ipv4Match) {
      connReq = new Uint8Array([
        0x05,
        0x01,
        0x00,
        0x01,
        Number(ipv4Match[1]),
        Number(ipv4Match[2]),
        Number(ipv4Match[3]),
        Number(ipv4Match[4]),
        (targetPort >> 8) & 0xff,
        targetPort & 0xff,
      ]);
    } else {
      const hostBytes = enc.encode(targetHost);
      connReq = new Uint8Array(7 + hostBytes.length);
      connReq[0] = 0x05;
      connReq[1] = 0x01; // CONNECT
      connReq[2] = 0x00; // RSV
      connReq[3] = 0x03; // ATYP = Domain Name (socks5h remote DNS)
      connReq[4] = hostBytes.length;
      connReq.set(hostBytes, 5);
      connReq[5 + hostBytes.length] = (targetPort >> 8) & 0xff;
      connReq[6 + hostBytes.length] = targetPort & 0xff;
    }
    await writer.write(connReq);

    // 4. Read CONNECT reply
    const replyHead = await reader.readExact(4);
    if (replyHead[0] !== 0x05 || replyHead[1] !== 0x00) {
      throw new Error(`SOCKS5 代理连接目标服务器失败 (code=${replyHead[1]})`);
    }

    const atyp = replyHead[3];
    if (atyp === 0x01) {
      await reader.readExact(6); // 4 IPv4 + 2 port
    } else if (atyp === 0x03) {
      const lenByte = await reader.readExact(1);
      await reader.readExact(lenByte[0] + 2);
    } else if (atyp === 0x04) {
      await reader.readExact(18); // 16 IPv6 + 2 port
    }
  } finally {
    reader.release();
    writer.releaseLock();
  }
}

async function performHttpConnectHandshake(
  socket: Socket,
  proxy: ParsedProxyConfig,
  targetHost: string,
  targetPort: number
): Promise<void> {
  const enc = new TextEncoder();
  const writer = socket.writable.getWriter();
  const reader = new StreamBufferReader(socket.readable);

  try {
    const lines = [
      `CONNECT ${targetHost}:${targetPort} HTTP/1.1`,
      `Host: ${targetHost}:${targetPort}`,
      `Proxy-Connection: keep-alive`,
    ];
    if (proxy.username) {
      const basic = btoa(`${proxy.username}:${proxy.password}`);
      lines.push(`Proxy-Authorization: Basic ${basic}`);
    }
    lines.push("", "");
    await writer.write(enc.encode(lines.join("\r\n")));

    const { headerBytes } = await reader.readUntilHeaderEnd();
    const headerText = new TextDecoder().decode(headerBytes);
    const statusLine = headerText.split("\r\n")[0] || "";
    const statusMatch = statusLine.match(/^HTTP\/\d\.\d\s+(\d{3})/);
    const statusCode = statusMatch ? Number(statusMatch[1]) : 0;
    if (statusCode !== 200) {
      throw new Error(`HTTP 代理 CONNECT 失败 (${statusLine || statusCode})`);
    }
  } finally {
    reader.release();
    writer.releaseLock();
  }
}

async function singleHopFetchViaProxy(
  targetUrlStr: string,
  userAgent: string,
  proxy: ParsedProxyConfig
): Promise<UpstreamHttpResponse> {
  const targetUrl = new URL(targetUrlStr);
  const isHttps = targetUrl.protocol === "https:";
  const targetHost = targetUrl.hostname;
  const targetPort = Number(targetUrl.port) || (isHttps ? 443 : 80);

  let rawSocket: Socket | null = null;
  let tlsTunnel: UserspaceTlsTunnel | null = null;

  try {
    rawSocket = connect(
      { hostname: proxy.host, port: proxy.port },
      {
        secureTransport: "off",
        allowHalfOpen: false,
      }
    );
    await rawSocket.opened;

    if (proxy.scheme === "socks5") {
      await performSocks5Handshake(rawSocket, proxy, targetHost, targetPort);
    } else if (isHttps) {
      await performHttpConnectHandshake(rawSocket, proxy, targetHost, targetPort);
    }

    const pathWithQuery = `${targetUrl.pathname || "/"}${targetUrl.search || ""}`;
    const hostHeader =
      (isHttps && targetPort === 443) || (!isHttps && targetPort === 80)
        ? targetHost
        : `${targetHost}:${targetPort}`;

    // If plain HTTP over HTTP proxy (no CONNECT tunnel), send full URL + Proxy-Authorization
    const reqTarget = !isHttps && proxy.scheme === "http" ? targetUrlStr : pathWithQuery;
    const reqLines = [
      `GET ${reqTarget} HTTP/1.1`,
      `Host: ${hostHeader}`,
      `User-Agent: ${userAgent}`,
      `Accept: */*`,
      `Accept-Encoding: identity`,
      `Connection: close`,
    ];
    if (!isHttps && proxy.scheme === "http" && proxy.username) {
      reqLines.push(`Proxy-Authorization: Basic ${btoa(`${proxy.username}:${proxy.password}`)}`);
    }
    reqLines.push("", "");
    const reqBytes = new TextEncoder().encode(reqLines.join("\r\n"));

    let readable: ReadableStream<Uint8Array>;
    if (isHttps) {
      tlsTunnel = await openUserspaceTlsTunnel(rawSocket, targetHost);
      await tlsTunnel.write(reqBytes);
      readable = tlsTunnel.readable;
    } else {
      const writer = rawSocket.writable.getWriter();
      try {
        await writer.write(reqBytes);
      } finally {
        writer.releaseLock();
      }
      readable = rawSocket.readable;
    }

    const reader = new StreamBufferReader(readable);
    try {
      const { headerBytes, rest } = await reader.readUntilHeaderEnd();
      const headerStr = new TextDecoder().decode(headerBytes);
      const headerLines = headerStr.split("\r\n");
      const statusMatch = (headerLines[0] || "").match(/^HTTP\/\d\.\d\s+(\d{3})/);
      const status = statusMatch ? Number(statusMatch[1]) : 0;

      const headers: Record<string, string> = {};
      for (const line of headerLines.slice(1)) {
        const colonIdx = line.indexOf(":");
        if (colonIdx !== -1) {
          const k = line.slice(0, colonIdx).trim().toLowerCase();
          const v = line.slice(colonIdx + 1).trim();
          headers[k] = v;
        }
      }

      const isChunked = (headers["transfer-encoding"] || "").toLowerCase().includes("chunked");
      const contentLength =
        headers["content-length"] && !Number.isNaN(Number(headers["content-length"]))
          ? Number(headers["content-length"])
          : null;

      const bodyBytes = await reader.readRemainingBody(rest, contentLength, isChunked);
      const bodyText = new TextDecoder("utf-8").decode(bodyBytes);
      return { status, headers, bodyText };
    } finally {
      reader.release();
    }
  } finally {
    if (tlsTunnel) {
      await tlsTunnel.close().catch(() => {});
    }
    if (rawSocket) {
      await rawSocket.close().catch(() => {});
    }
  }
}

/**
 * Fetches `url` through a SOCKS5 or HTTP proxy with redirect following (up to 4 hops) and timeout.
 */
export async function fetchViaProxy(
  url: string,
  userAgent: string,
  proxySpec: string,
  timeoutMs = 15000
): Promise<UpstreamHttpResponse> {
  const proxy = parseProxyConfig(proxySpec);

  const run = async (): Promise<UpstreamHttpResponse> => {
    let currentUrl = url;
    for (let hop = 0; hop < 4; hop++) {
      const resp = await singleHopFetchViaProxy(currentUrl, userAgent, proxy);
      if ([301, 302, 303, 307, 308].includes(resp.status) && resp.headers.location) {
        currentUrl = new URL(resp.headers.location, currentUrl).toString();
        continue;
      }
      return resp;
    }
    throw new Error("订阅重定向次数过多");
  };

  return Promise.race([
    run(),
    new Promise<UpstreamHttpResponse>((_, reject) =>
      setTimeout(() => reject(new Error("代理拉取超时 (15s)")), timeoutMs)
    ),
  ]);
}
