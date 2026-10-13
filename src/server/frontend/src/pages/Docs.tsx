// /docs: how to set up and use Hawk, public like the login page. The pages
// are Markdown in docs/, turned into HTML at build time (vite.config.ts),
// so the content is static and the same for everyone.
import { type JSX, type MouseEvent, useEffect, useState } from "react";

import start from "../../docs/01-start.md";
import relay from "../../docs/02-relay.md";
import machine from "../../docs/03-machine.md";
import machineConfig from "../../docs/04-machine-config.md";
import accounts from "../../docs/05-accounts.md";
import usage from "../../docs/06-using.md";
import sharing from "../../docs/07-sharing.md";
import security from "../../docs/08-security.md";
import troubleshooting from "../../docs/09-troubleshooting.md";
import updates from "../../docs/10-updates.md";
import { Logo } from "../ui.js";

type Doc = typeof start;

// In reading order. The first is /docs itself.
const PAGES: { slug: string; doc: Doc }[] = [
  { slug: "", doc: start },
  { slug: "relay", doc: relay },
  { slug: "machine", doc: machine },
  { slug: "machine-config", doc: machineConfig },
  { slug: "accounts", doc: accounts },
  { slug: "using", doc: usage },
  { slug: "sharing", doc: sharing },
  { slug: "security", doc: security },
  { slug: "updates", doc: updates },
  { slug: "troubleshooting", doc: troubleshooting },
];

const href = (slug: string): string => (slug === "" ? "/docs" : `/docs/${slug}`);

function slugFromPath(path: string): string {
  return path.replace(/^\/docs\/?/, "").replace(/\/+$/, "");
}

export function DocsPage(): JSX.Element {
  // The path and hash, re-read on every navigation within the docs.
  const [location, setLocation] = useState(() => ({
    path: window.location.pathname,
    hash: window.location.hash,
  }));

  useEffect(() => {
    const onPop = (): void => setLocation({ path: window.location.pathname, hash: window.location.hash });
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const slug = slugFromPath(location.path);
  const index = PAGES.findIndex((page) => page.slug === slug);
  const page = PAGES[index];

  useEffect(() => {
    const before = document.title;
    document.title = page === undefined ? "Not found · Hawk docs" : `${page.doc.title} · Hawk docs`;
    return () => {
      document.title = before;
    };
  }, [page]);

  // A new page starts at the top, or at the heading its link names.
  useEffect(() => {
    const id = decodeURIComponent(location.hash.slice(1));
    const target = id === "" ? null : document.getElementById(id);
    if (target !== null) target.scrollIntoView();
    else window.scrollTo(0, 0);
  }, [location]);

  // Links between docs pages stay in the page; code blocks copy.
  const onClick = (event: MouseEvent<HTMLElement>): void => {
    const target = event.target as HTMLElement;
    const copy = target.closest<HTMLButtonElement>("button[data-copy]");
    if (copy !== null) {
      const text = copy.parentElement?.querySelector("pre")?.textContent ?? "";
      navigator.clipboard.writeText(text).then(
        () => {
          copy.textContent = "Copied";
          window.setTimeout(() => (copy.textContent = "Copy"), 1500);
        },
        () => {},
      );
      return;
    }
    const link = target.closest<HTMLAnchorElement>("a[href]");
    if (link === null || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    const url = new URL(link.href);
    if (url.origin !== window.location.origin || !/^\/docs(\/|$)/.test(url.pathname)) return;
    if (url.pathname === window.location.pathname && url.hash !== "") return; // the browser scrolls to it
    event.preventDefault();
    window.history.pushState(null, "", url.pathname + url.hash);
    setLocation({ path: url.pathname, hash: url.hash });
  };

  const previous = index > 0 ? PAGES[index - 1] : undefined;
  const next = index >= 0 ? PAGES[index + 1] : undefined;

  return (
    <div className="docs" onClick={onClick}>
      <header className="topbar docs-bar">
        <a className="brand" href="/docs">
          <Logo size={18} />
          <span className="brand-name">HAWK</span>
        </a>
        <span className="docs-crumb label">Documentation</span>
        <span className="spacer" />
        <a className="btn btn-ghost btn-sm" href="/">
          Dashboard
        </a>
      </header>

      <div className="docs-body">
        <nav className="docs-nav" aria-label="Documentation">
          <ul>
            {PAGES.map((entry) => (
              <li key={entry.slug}>
                <a href={href(entry.slug)} aria-current={entry === page ? "page" : undefined}>
                  {entry.doc.title}
                </a>
                {entry === page && (
                  <ul className="docs-toc">
                    {entry.doc.headings
                      .filter((heading) => heading.depth === 2)
                      .map((heading) => (
                        <li key={heading.id}>
                          <a href={`${href(entry.slug)}#${heading.id}`}>{heading.text}</a>
                        </li>
                      ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        </nav>

        <main className="docs-main">
          {page === undefined ? (
            <article className="docs-content">
              <h1>No such page</h1>
              <p>
                There's nothing at <code>{location.path}</code>. Start from <a href="/docs">Getting started</a>.
              </p>
            </article>
          ) : (
            // Built from the Markdown in docs/ at build time; nothing in it
            // comes from a user or the relay.
            <article key={page.slug} className="docs-content" dangerouslySetInnerHTML={{ __html: page.doc.html }} />
          )}
          {page !== undefined && (
            <nav className="docs-pager" aria-label="Next and previous page">
              {previous !== undefined ? (
                <a href={href(previous.slug)}>
                  <span className="label">Previous</span>
                  {previous.doc.title}
                </a>
              ) : (
                <span />
              )}
              {next !== undefined && (
                <a href={href(next.slug)} className="next">
                  <span className="label">Next</span>
                  {next.doc.title}
                </a>
              )}
            </nav>
          )}
        </main>
      </div>
    </div>
  );
}
