import { readFileSync } from "node:fs";

export interface TlsConfig {
  cert: Buffer;
  key: Buffer;
}

// TLS material comes from TLS_CERT_PATH/TLS_KEY_PATH when set (point these at
// a real certificate in any non-local deployment), falling back to the
// self-signed dev cert from `bun run certs` when present. Returns undefined
// — plain http/ws — only when neither is available, which is fine for
// localhost-only development and nothing else.
export function loadTlsConfig(defaultCertPath: string, defaultKeyPath: string): TlsConfig | undefined {
  const certPath = process.env.TLS_CERT_PATH ?? defaultCertPath;
  const keyPath = process.env.TLS_KEY_PATH ?? defaultKeyPath;

  try {
    return { cert: readFileSync(certPath), key: readFileSync(keyPath) };
  } catch {
    return undefined;
  }
}
