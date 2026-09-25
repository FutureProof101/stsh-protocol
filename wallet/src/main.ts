/**
 * Wallet entry point (wallet-build Commit 6). Vanilla TS + Vite — no framework.
 */

import "./styles.css";
import { mountApp } from "./ui/app";

const container = document.getElementById("app");
if (container) {
  mountApp(container, import.meta.env as unknown as Record<string, string | undefined>);
}
