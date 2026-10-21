# Guard Desktop Client

macOS menu-bar app for Guard. Lives in the system tray (no Dock icon) and shows
a popover panel for the WireGuard tunnel that authenticates and proxies traffic.

Right now the UI is a **placeholder** — the connect/disconnect toggle and tunnel
details are mocked in [src/App.tsx](src/App.tsx). Wire these up to the WireGuard
backend via Tauri commands.

## Stack

- **Tauri 2** (Rust) — tray icon, popover window, app lifecycle
  - [`tray-icon`](src-tauri/src/lib.rs) with left-click toggle + right-click menu
  - `tauri-plugin-positioner` anchors the popover under the tray icon
  - `ActivationPolicy::Accessory` hides the Dock icon (menu-bar only app)
- **React + TypeScript + Vite** — frontend in [src/](src/)

## Develop

```sh
npm install
npm run tauri dev     # launches the tray app with hot reload
```

The tray icon appears in the menu bar. **Left-click** toggles the popover;
**right-click** opens the menu (Open / Quit). The popover auto-hides on blur.

## Build

```sh
npm run tauri build   # produces a .app / .dmg bundle
```

## Recommended IDE Setup

- [VS Code](https://code.visualstudio.com/) + [Tauri](https://marketplace.visualstudio.com/items?itemName=tauri-apps.tauri-vscode) + [rust-analyzer](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust-analyzer)
