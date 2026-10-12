import react from "@vitejs/plugin-react";
import { Marked, type Tokens } from "marked";
import { type Plugin, defineConfig } from "vite";

// The /docs pages are Markdown in docs/, turned into HTML here at build
// time, so the dashboard ships no Markdown parser. Each file becomes
// { title, html, headings }: the title is its first `# ` heading, and every
// `##`/`###` heading gets an id to link to.
function markdown(): Plugin {
  const slug = (text: string): string =>
    text
      .toLowerCase()
      .replace(/<[^>]*>/g, "")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "");
  return {
    name: "hawk-markdown",
    transform(source, id) {
      if (!id.endsWith(".md")) return null;
      let title = "";
      const headings: { id: string; text: string; depth: number }[] = [];
      const marked = new Marked({
        renderer: {
          heading({ tokens, depth, text }: Tokens.Heading) {
            const inner = this.parser.parseInline(tokens);
            if (depth === 1) {
              title = text.replace(/`/g, "");
              return `<h1>${inner}</h1>\n`;
            }
            const anchor = slug(text);
            if (depth <= 3) headings.push({ id: anchor, text: text.replace(/`/g, ""), depth });
            return `<h${depth} id="${anchor}"><a class="anchor" href="#${anchor}">${inner}</a></h${depth}>\n`;
          },
          code({ text }: Tokens.Code) {
            const escaped = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
            return `<div class="code"><pre><code>${escaped}</code></pre><button type="button" class="copy" data-copy>Copy</button></div>\n`;
          },
        },
        hooks: {
          // Wide tables scroll on their own instead of the page.
          postprocess: (html) =>
            html.replace(/<table>/g, '<div class="table-wrap"><table>').replace(/<\/table>/g, "</table></div>"),
        },
      });
      const html = marked.parse(source, { async: false });
      return { code: `export default ${JSON.stringify({ title, html, headings })};`, map: null };
    },
  };
}

// Dev server proxies API/WS calls to the relay so the dashboard can be
// run with `bun run dev` without CORS or a separate origin to configure.
// The relay serves wss/https using a self-signed dev cert (see
// scripts/generate-dev-cert.sh), so `secure: false` here just skips
// cert verification on this local dev-only hop — it has no bearing on the
// TLS the real client/dashboard connect over in production.
export default defineConfig({
  plugins: [markdown(), react()],
  server: {
    proxy: {
      "/api": { target: "https://127.0.0.1:8080", secure: false },
      "/v1/dashboard": { target: "wss://127.0.0.1:8080", ws: true, secure: false },
    },
  },
  build: {
    outDir: "dist",
  },
});
