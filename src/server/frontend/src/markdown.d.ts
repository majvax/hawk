// A page in docs/, as the Markdown plugin in vite.config.ts turns it into
// a module at build time.
declare module "*.md" {
  const doc: {
    title: string;
    html: string;
    headings: { id: string; text: string; depth: number }[];
  };
  export default doc;
}
