import { describe, expect, test } from "bun:test";

import { MAX_TEXT_UNITS, MODIFIER_ALT, MODIFIER_CTRL, MODIFIER_SHIFT, MODIFIER_WIN } from "./protocol.js";
import { chordFor, isShortcut, strokeFor, textChange, typingFor } from "./touchKeyboard.js";

describe("strokeFor", () => {
  test("letters, with Shift for capitals", () => {
    expect(strokeFor("a")).toEqual({ code: "KeyA", shift: false });
    expect(strokeFor("Z")).toEqual({ code: "KeyZ", shift: true });
  });

  test("digits and what Shift makes of them", () => {
    expect(strokeFor("0")).toEqual({ code: "Digit0", shift: false });
    expect(strokeFor("!")).toEqual({ code: "Digit1", shift: true });
    expect(strokeFor("(")).toEqual({ code: "Digit9", shift: true });
    expect(strokeFor(")")).toEqual({ code: "Digit0", shift: true });
  });

  test("punctuation, space, Enter and Tab", () => {
    expect(strokeFor(" ")).toEqual({ code: "Space", shift: false });
    expect(strokeFor("\n")).toEqual({ code: "Enter", shift: false });
    expect(strokeFor("\t")).toEqual({ code: "Tab", shift: false });
    expect(strokeFor("?")).toEqual({ code: "Slash", shift: true });
    expect(strokeFor("\\")).toEqual({ code: "Backslash", shift: false });
    expect(strokeFor("~")).toEqual({ code: "Backquote", shift: true });
  });

  test("a phone's curly quotes type straight ones", () => {
    expect(strokeFor("’")).toEqual({ code: "Quote", shift: false });
    expect(strokeFor("“")).toEqual({ code: "Quote", shift: true });
  });

  test("nothing for what no US key types", () => {
    expect(strokeFor("é")).toBeNull();
    expect(strokeFor("你")).toBeNull();
    expect(strokeFor("😀")).toBeNull();
  });

});

describe("typingFor", () => {
  test("text goes as text, whatever it's written in", () => {
    expect(typingFor("été 😀 你好", true)).toEqual([{ kind: "text", text: "été 😀 你好" }]);
  });

  test("line breaks and tabs are their keys, between runs of text", () => {
    expect(typingFor("a\tb\nc", true)).toEqual([
      { kind: "text", text: "a" },
      { kind: "key", code: "Tab", shift: false },
      { kind: "text", text: "b" },
      { kind: "key", code: "Enter", shift: false },
      { kind: "text", text: "c" },
    ]);
    expect(typingFor("\r\n\r", true)).toEqual([
      { kind: "key", code: "Enter", shift: false },
      { kind: "key", code: "Enter", shift: false },
    ]);
  });

  test("other controls are dropped", () => {
    expect(typingFor("a\u0000\u0007\u007f\u0085b", true)).toEqual([{ kind: "text", text: "ab" }]);
  });

  test("long text is split, never more than a machine takes at once", () => {
    const runs = typingFor("x".repeat(MAX_TEXT_UNITS * 2 + 3), true);
    expect(runs.map((run) => (run.kind === "text" ? run.text.length : 0))).toEqual([
      MAX_TEXT_UNITS,
      MAX_TEXT_UNITS,
      3,
    ]);
  });

  test("a split never cuts a surrogate pair", () => {
    const text = "x".repeat(MAX_TEXT_UNITS - 1) + "😀".repeat(3);
    const runs = typingFor(text, true).map((run) => (run.kind === "text" ? run.text : ""));
    expect(runs.join("")).toBe(text);
    expect(runs[0]).toBe("x".repeat(MAX_TEXT_UNITS - 1));
    for (const run of runs) {
      expect(run.length).toBeLessThanOrEqual(MAX_TEXT_UNITS);
      expect(run.isWellFormed()).toBe(true);
    }
  });

  test("an older machine gets US keys, and nothing for what has none", () => {
    expect(typingFor("Hé!\n", false)).toEqual([
      { kind: "key", code: "KeyH", shift: true },
      { kind: "key", code: "Digit1", shift: true },
      { kind: "key", code: "Enter", shift: false },
    ]);
  });
});

describe("isShortcut", () => {
  test("Ctrl, Alt and Win make one; Shift alone doesn't", () => {
    expect(isShortcut([])).toBe(false);
    expect(isShortcut(["ShiftLeft"])).toBe(false);
    expect(isShortcut(["ControlLeft"])).toBe(true);
    expect(isShortcut(["ShiftLeft", "AltLeft"])).toBe(true);
    expect(isShortcut(new Set(["MetaLeft"]))).toBe(true);
  });
});

describe("textChange", () => {
  test("typing adds to the end", () => {
    expect(textChange("__", "__h")).toEqual({ deleted: 0, inserted: "h" });
  });

  test("Backspace takes from the end", () => {
    expect(textChange("__he", "__h")).toEqual({ deleted: 1, inserted: "" });
    expect(textChange("__", "_")).toEqual({ deleted: 1, inserted: "" });
  });

  test("autocorrect replaces from where the text differs", () => {
    expect(textChange("__teh", "__the ")).toEqual({ deleted: 2, inserted: "he " });
  });

  test("an IME turning letters into a word", () => {
    expect(textChange("__ni", "__你")).toEqual({ deleted: 2, inserted: "你" });
  });

  test("counts characters, not UTF-16 units", () => {
    expect(textChange("__😀", "__")).toEqual({ deleted: 1, inserted: "" });
    expect(textChange("__😀", "__😃")).toEqual({ deleted: 1, inserted: "😃" });
  });

  test("no change, nothing to do", () => {
    expect(textChange("__", "__")).toEqual({ deleted: 0, inserted: "" });
  });
});

describe("chordFor", () => {
  test("a character with Ctrl, Alt or Win, as modifier bits", () => {
    expect(chordFor("a", ["ControlLeft"])).toEqual({ kind: "chord", text: "a", modifiers: MODIFIER_CTRL });
    expect(chordFor("é", new Set(["AltLeft", "ShiftLeft", "MetaLeft"]))).toEqual({
      kind: "chord",
      text: "é",
      modifiers: MODIFIER_ALT | MODIFIER_SHIFT | MODIFIER_WIN,
    });
  });

  test("a capital goes lower case unless Shift is latched", () => {
    expect(chordFor("C", ["ControlLeft"])?.text).toBe("c");
    expect(chordFor("É", ["AltLeft"])?.text).toBe("é");
    expect(chordFor("C", ["ControlLeft", "ShiftLeft"])?.text).toBe("C");
    // A lower case that isn't one unit keeps the character as it was.
    expect(chordFor("İ", ["ControlLeft"])?.text).toBe("İ");
  });

  test("no shortcut without Ctrl, Alt or Win", () => {
    expect(chordFor("a", [])).toBeNull();
    expect(chordFor("a", ["ShiftLeft"])).toBeNull();
  });

  test("only for one character a key could type", () => {
    expect(chordFor("\n", ["ControlLeft"])).toBeNull();
    expect(chordFor("\t", ["ControlLeft"])).toBeNull();
    expect(chordFor("😀", ["ControlLeft"])).toBeNull();
    expect(chordFor("ab", ["ControlLeft"])).toBeNull();
    expect(chordFor("", ["ControlLeft"])).toBeNull();
  });
});
