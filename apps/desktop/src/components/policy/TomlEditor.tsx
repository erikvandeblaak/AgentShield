import { useEffect, useRef } from "react";
import { minimalSetup } from "codemirror";
import { EditorState } from "@codemirror/state";
import { EditorView, highlightActiveLine, highlightActiveLineGutter, keymap, lineNumbers } from "@codemirror/view";
import { indentWithTab } from "@codemirror/commands";
import { HighlightStyle, StreamLanguage, syntaxHighlighting } from "@codemirror/language";
import { toml } from "@codemirror/legacy-modes/mode/toml";
import { tags } from "@lezer/highlight";
import { cx } from "../ui";

// Colours come from CSS variables so the same style works in dark and light mode.
const highlight = HighlightStyle.define([
  { tag: tags.comment, color: "var(--fg-3)", fontStyle: "italic" },
  { tag: tags.string, color: "var(--ok)" },
  { tag: [tags.number, tags.bool], color: "var(--warn)" },
  { tag: tags.atom, color: "var(--accent-3)", fontWeight: "600" },
  { tag: [tags.propertyName, tags.definition(tags.propertyName)], color: "var(--info)" },
  { tag: [tags.bracket, tags.punctuation, tags.operator], color: "var(--fg-2)" },
  { tag: tags.invalid, color: "var(--danger)" },
]);

const tomlLanguage = StreamLanguage.define(toml);

interface TomlEditorProps {
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  height?: number | string;
  ariaLabel: string;
  className?: string;
}

/** CodeMirror 6 TOML editor (bundled locally; legacy stream mode). Controlled through `value`. */
export function TomlEditor({ value, onChange, readOnly = false, height = 420, ariaLabel, className }: TomlEditorProps) {
  const host = useRef<HTMLDivElement>(null);
  const view = useRef<EditorView | null>(null);
  const changeRef = useRef(onChange);
  changeRef.current = onChange;
  const initial = useRef(value);

  useEffect(() => {
    if (!host.current) return;
    const v = new EditorView({
      parent: host.current,
      state: EditorState.create({
        doc: initial.current,
        extensions: [
          minimalSetup,
          lineNumbers(),
          ...(readOnly ? [] : [highlightActiveLine(), highlightActiveLineGutter(), keymap.of([indentWithTab])]),
          tomlLanguage,
          syntaxHighlighting(highlight),
          EditorState.readOnly.of(readOnly),
          EditorState.tabSize.of(2),
          EditorView.contentAttributes.of({ "aria-label": ariaLabel, spellcheck: "false", autocapitalize: "off" }),
          EditorView.updateListener.of((u) => {
            if (u.docChanged) changeRef.current?.(u.state.doc.toString());
          }),
        ],
      }),
    });
    view.current = v;
    return () => {
      v.destroy();
      view.current = null;
    };
    // The editor is created once per mode; value changes are synced below.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [readOnly]);

  // External value changes (load, revert, rule insertion) replace the document.
  useEffect(() => {
    const v = view.current;
    if (!v) return;
    const current = v.state.doc.toString();
    if (current !== value) v.dispatch({ changes: { from: 0, to: current.length, insert: value } });
  }, [value]);

  return <div ref={host} className={cx("cm-host overflow-hidden rounded-lg border border-line bg-bg-2", className)} style={{ height }} />;
}
