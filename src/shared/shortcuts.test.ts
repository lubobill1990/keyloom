import { describe, expect, test } from "bun:test";
import { shortcutAction } from "./shortcuts";

const key = (value: string, modifiers: Partial<Parameters<typeof shortcutAction>[0]> = {}) => ({
  key: value, ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, ...modifiers,
});

describe("desktop keyboard policy", () => {
  test("classifies browser-only keys for page-level suppression", () => {
    for (const value of ["j", "J", "p", "o", "r", "u", "d", "+", "=", "-", "0"]) {
      expect(shortcutAction(key(value, { ctrlKey: true }))).toBe("block");
      expect(shortcutAction(key(value, { metaKey: true }))).toBe("block");
    }
    for (const value of ["i", "j", "c", "s", "n"]) {
      expect(shortcutAction(key(value, { ctrlKey: true, shiftKey: true }))).toBe("block");
    }
    for (const value of ["F5", "F12"]) expect(shortcutAction(key(value))).toBe("block");
  });
  test("retains application shortcuts and supports in-app find", () => {
    for (const [value, action] of [["k", "search"], ["f", "search"], ["s", "save"], ["l", "lock"], ["n", "new"]] as const) {
      expect(shortcutAction(key(value, { ctrlKey: true }))).toBe(action);
    }
  });
  test("preserves typing, editing, word navigation and AltGr combinations", () => {
    for (const value of ["j", "p", "r", "u", "s", "k", "f"]) expect(shortcutAction(key(value))).toBeNull();
    for (const value of ["c", "v", "x", "a", "z", "y", "ArrowLeft", "ArrowRight", "Home", "End", "Backspace", "Delete"]) {
      expect(shortcutAction(key(value, { ctrlKey: true }))).toBeNull();
    }
    expect(shortcutAction(key("v", { ctrlKey: true, shiftKey: true }))).toBeNull();
    expect(shortcutAction(key("j", { ctrlKey: true, altKey: true }))).toBeNull();
  });
});
