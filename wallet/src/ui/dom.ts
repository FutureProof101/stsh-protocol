/**
 * Tiny DOM helpers (wallet-build Commit 6) — no framework (brief: vanilla TS).
 */

type Attrs = Record<string, string | number | boolean | ((e: Event) => void)>;

/** Create an element with attributes/handlers and children. */
export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  children: Array<Node | string> = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (typeof value === "function") {
      node.addEventListener(key.replace(/^on/, "").toLowerCase(), value as EventListener);
    } else if (key === "class") {
      node.className = String(value);
    } else if (value === false) {
      // skip falsy boolean attributes
    } else {
      node.setAttribute(key, String(value));
    }
  }
  for (const child of children) {
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

/** Remove all children of a node. */
export function clear(node: HTMLElement): void {
  node.replaceChildren();
}
