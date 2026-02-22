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
      highlight={(code) => Prism.highlight(code ?? "", Prism.languages.toml, "toml")}
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
