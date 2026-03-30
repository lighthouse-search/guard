"use client";

import Editor from "react-simple-code-editor";
import Prism from "prismjs";
import "prismjs/components/prism-toml";
import "prismjs/themes/prism-tomorrow.css";

export default function ConfigEditor(props: any) {

  return (
    <Editor
      value={props.value}
      onValueChange={props.onChange}
      highlight={(code) => {
        const html = Prism.highlight(code ?? "", Prism.languages.toml, "toml");
        // Prism's TOML grammar marks section headers as class="token table".
        // Tailwind v4 generates .table { display: table } which makes those spans
        // block-level and breaks the editor layout. Rename to avoid the collision.
        return html.replace(/\btoken table\b/g, "token toml-section");
      }}
      padding={24}
      style={{
        fontFamily: '"Fira Code", "Fira Mono", "Cascadia Code", monospace',
        fontSize: 13,
        backgroundColor: "var(--editor-bg)",
        color: "var(--editor-fg)",
        overflowX: "auto",
        minHeight: "100vh",
        width: "100%",
      }}
    />
  );
}
