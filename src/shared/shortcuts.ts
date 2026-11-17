export type ShortcutAction = "search" | "save" | "lock" | "new" | "block";

type ShortcutKey = Pick<KeyboardEvent, "key" | "ctrlKey" | "metaKey" | "altKey" | "shiftKey">;

const browserKeys = new Set(["j", "o", "p", "r", "u", "d", "+", "=", "-", "0"]);

export function shortcutAction(event: ShortcutKey): ShortcutAction | null {
  if (event.altKey) return null;
  const key = event.key.toLowerCase();
  if (key === "f5" || key === "f12") return "block";
  if (!(event.ctrlKey || event.metaKey)) return null;
  if (event.shiftKey && ["i", "j", "c", "s", "n"].includes(key)) return "block";
  if (key === "k" || key === "f") return "search";
  if (key === "s") return "save";
  if (key === "l") return "lock";
  if (key === "n") return "new";
  return browserKeys.has(key) ? "block" : null;
}
