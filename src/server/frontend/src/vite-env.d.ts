// The build-time settings this dashboard reads (see relay.ts).
interface ImportMetaEnv {
  // "1" for a dashboard not served by a relay: the desktop app, a static host.
  readonly VITE_HAWK_STANDALONE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
