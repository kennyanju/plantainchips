# CloudSecure Technical Architecture, ADRs & UX Foundation

> **Authored by**: `agency-ux-architect`, `agency-software-architect`, `agency-desktop-app-engineer`, `agency-webassembly-engineer`, `agency-rust-refactoring-specialist`  
> **Deliverable Type**: Phase 2 Technical Foundation (`project-docs/cloudsecure-architecture.md`)

---

## 1. Architecture Decision Records (ADRs)

### ADR-001: 100% Pure Rust (`egui` + `eframe` + `wgpu`) Instead of Electron or Tauri
- **Status**: Accepted
- **Context**: `getartcraft.com` (`storytold/craft-launcher` and the 13 Craft Apps) explicitly rejects Electron and Tauri in favor of pure Rust (`egui` 0.36 + `eframe` + `wgpu` for native desktop and `trunk` WebAssembly for the browser).
- **Decision**: Build `launchersecure` and all 13 CloudSecure CNAPP applications using `egui` + `eframe` + `wgpu` (`unsafe_code = "forbid"`), sharing `crates/cloudsecure-ui`.
- **Consequences**:
  - *Gained*: Single 100% Rust codebase compiles to macOS, Windows, Linux, FreeBSD, and WebAssembly (`wasm32-unknown-unknown`); `< 15 MB` native binaries; `< 80 MB` idle RAM; deterministic offscreen rendering via `egui_kittest`; zero JS-to-Rust IPC serialization overhead inside the app UI.
  - *Given up*: HTML/CSS DOM styling inside the desktop apps (mitigated by building the marketing/docs portal `cloudsecure-site` in Rust `axum` + HTML/CSS while embedding the `egui` Wasm canvases).

### ADR-002: Hexagonal Domain Core with 4-Way Command Bus
- **Status**: Accepted
- **Context**: Security engineers need to run the exact same CSPM, DSPM, CWPP, CIEM, ASPM, WAAS, and CDR logic interactively on desktop, in browser Wasm, in headless CI/CD pipelines, and via AI agents (MCP).
- **Decision**: Every app's domain crate (`crates/*` and `apps/<app>/src/engine.rs`) is a pure, synchronous/channel-driven state machine accepting serializable `Command` enums. The `egui` UI, `<app>-cli`, JSON-RPC stdio server, and MCP server are thin adapters around `CloudSecureAppEngine`.
- **Consequences**: 100% behavioral parity across GUI, CLI, JSON-RPC, and MCP; deterministic replay of any user session.

### ADR-003: Unified Resource Query Language (`cloudsecure-rql`)
- **Status**: Accepted
- **Context**: Enterprise CNAPP platforms unify multi-cloud posture and telemetry under RQL (`config from`, `network from`, `event from`, `iam from`, `data from`).
- **Decision**: Implement a shared, zero-copy Rust parser (`winnow`) and query planner in `crates/cloudsecure-rql` used by all 13 applications and the `/rql` web playground.
- **Consequences**: Learning one query grammar unlocks all 13 CloudSecure tools; queries can join across posture, network, identity, and data classifications in `GraphSecure` and `ComplianceSecure`.

### ADR-004: Mandatory Secret & PII Redaction at Ingestion Boundary
- **Status**: Accepted
- **Context**: `DataSecure` (DSPM) and `CodeSecure` (ASPM) inspect files and buckets that may contain real credentials or PII/PCI.
- **Decision**: Wrap all sensitive pattern hits in `cloudsecure_types::RedactedSecret`, which immediately masks the middle characters, computes a keyed SHA-256 fingerprint, and runs `zeroize::Zeroize` on the raw buffer before returning.
- **Consequences**: Zero plaintext secrets can ever leak into `.csec` snapshots, SARIF reports, MCP responses, or UI tables.

### ADR-005: Read-Only Assessment Default & Two-Step Signed Remediation
- **Status**: Accepted
- **Context**: Automated cloud remediation can cause catastrophic production outages if executed blindly.
- **Decision**: All cloud connectors operate in strictly read-only mode. Remediation engines output reviewable `.patch` / `.tf` / `.sh` artifacts with SHA-256 hashes. Applying any change requires explicit CLI flag `--apply-remediation --confirm-sha256 <hash>` or two-step human confirmation in the GUI.
- **Consequences**: Eliminates accidental destructive mutations of cloud infrastructure.

### ADR-006: Deflated Font & Asset Embedding for Wasm Size Gate (`< 900 KB`)
- **Status**: Accepted
- **Context**: `storytold/photocraft` disables `egui`'s `default_fonts` feature because uncompressed embedded fonts bloat `.wasm` binaries.
- **Decision**: Disable `default-features` on `egui` and load `flate2`-compressed font bytes in `crates/cloudsecure-ui/src/egui_fonts.rs`, combined with `wasm-opt -Oz --strip-debug --dce`.
- **Consequences**: Keeps every Wasm app bundle under `900 KB` compressed for sub-second browser startup.

### ADR-007: Ed25519 + SHA-256 Staged Update Manifest for `launchersecure`
- **Status**: Accepted
- **Context**: A broken or unverified auto-updater is a supply-chain and availability vulnerability.
- **Decision**: Every release publishes `manifest.json` signed with an offline Ed25519 key (`ed25519-dalek`) and per-artifact SHA-256 digests. The launcher verifies both signature and hash before unpacking and keeps the `N-1` binary for instant rollback.
- **Consequences**: Cryptographic protection against mirror tampering and zero stranded installations.

### ADR-008: Rust `axum` + Static Site Generator for `cloudsecure-site`
- **Status**: Accepted
- **Context**: The user requested all applications and program components be built in Rust while replicating `getartcraft.com`.
- **Decision**: Implement `web/cloudsecure-site` in Rust using `axum` for live serving (`/api/rql/evaluate`) and a built-in static generator (`--build-static`) that emits pre-rendered HTML, CSS, JS theme controller, and embedded Wasm apps.
- **Consequences**: Zero Node.js runtime dependency required to run or build the web portal; shares the exact `cloudsecure-rql` and `cloudsecure-types` crates with the desktop suite.

---

## 2. CSS Design System Foundation (`web/cloudsecure-site/static/css/design-system.css`)

Developers implementing `cloudsecure-site` MUST use this exact CSS variable and layout foundation (replicating `getartcraft.com`'s architectural grid and passing all `contrast-check.py` WCAG AA checks):

```css
/* web/cloudsecure-site/static/css/design-system.css */
:root {
  /* Light Theme: Warm Technical Paper (getartcraft.com baseline) */
  --bg: #f2f1ee;
  --bg-elevated: #e6e4df;
  --ink-strong: #0b0b0c;   /* 17.42:1 vs --bg (AAA) */
  --ink: #1c1c1e;          /* 15.10:1 vs --bg (AAA) */
  --muted: #4a4a46;        /* 7.88:1 vs --bg (AAA) */
  --faint: #6b6a65;        /* 4.80:1 vs --bg (AA) */
  --line: #c8c6c0;         /* 1px structural hairline */
  --line-strong: #6b6a65;  /* 4.80:1 interactive border (AA >= 3:1) */
  --invert-bg: #0b0b0c;
  --invert-fg: #f2f1ee;
  --accent-ink: #b7410e;   /* 4.92:1 Rust Oxide (AA) */

  /* Severity Tokens - Light Mode (all >= 5.4:1 vs --bg) */
  --sev-critical: #a81e23; /* 6.47:1 */
  --sev-high: #944800;     /* 5.84:1 */
  --sev-medium: #6e5600;   /* 5.41:1 */
  --sev-low: #1d4ed8;      /* 5.92:1 */
  --sev-pass: #1b6535;     /* 6.28:1 */

  /* Per-App Semantic Ink - Light Mode */
  --app-posturesecure: #0f52ba;
  --app-datasecure: #0d6e52;
  --app-workloadsecure: #8b3a0e;
  --app-identitysecure: #6b21a8;
  --app-codesecure: #1e5631;
  --app-waassecure: #9d174d;
  --app-threatsecure: #a81e23;
  --app-graphsecure: #4338ca;
  --app-netsecure: #0e606b;
  --app-aisecure: #7c2d12;
  --app-supplysecure: #374151;
  --app-policysecure: #854d0e;
  --app-compliancesecure: #115e59;

  /* Typography */
  --font-display: 'Archivo', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-serif: 'Instrument Serif', Georgia, serif;
  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-mono: 'Geist Mono', 'JetBrains Mono', monospace;

  /* Fluid Type Scale */
  --text-hero: clamp(2.25rem, 4.5vw + 1rem, 4.25rem);
  --text-h1: clamp(1.875rem, 3vw + 0.75rem, 3.25rem);
  --text-h2: clamp(1.5rem, 2vw + 0.5rem, 2.25rem);
  --text-h3: clamp(1.125rem, 1.2vw + 0.5rem, 1.5rem);
  --text-body-lg: clamp(1rem, 0.4vw + 0.9rem, 1.125rem);
  --text-body: 1rem;
  --text-sm: 0.875rem;
  --text-hud: 0.6875rem;

  /* Spacing System (4px base) */
  --space-1: 0.25rem;
  --space-2: 0.5rem;
  --space-3: 0.75rem;
  --space-4: 1rem;
  --space-6: 1.5rem;
  --space-8: 2rem;
  --space-10: 2.5rem;
  --space-14: 3.5rem;
  --space-20: 5rem;

  /* Container Width */
  --container-max: 1280px;
  --nav-height: 3rem; /* 48px */
}

[data-theme="dark"] {
  --bg: #0b0b0c;
  --bg-elevated: #141417;
  --ink-strong: #f2f1ee;   /* 17.42:1 vs --bg (AAA) */
  --ink: #e2e1dc;          /* 14.85:1 vs --bg (AAA) */
  --muted: #b4b3ae;        /* 9.37:1 vs --bg (AAA) */
  --faint: #85858e;        /* 5.38:1 vs --bg (AA) */
  --line: #26262b;
  --line-strong: #85858e;  /* 5.38:1 interactive border (AA >= 3:1) */
  --invert-bg: #f2f1ee;
  --invert-fg: #0b0b0c;
  --accent-ink: #ff6b35;   /* 6.94:1 Rust Oxide Dark (AA) */

  --sev-critical: #ff6b6b; /* 7.09:1 */
  --sev-high: #ffb347;     /* 11.05:1 */
  --sev-medium: #facc15;   /* 12.75:1 */
  --sev-low: #60a5fa;      /* 7.86:1 */
  --sev-pass: #4ade80;     /* 11.29:1 */

  --app-posturesecure: #5c9dff;
  --app-datasecure: #34d399;
  --app-workloadsecure: #fb923c;
  --app-identitysecure: #c084fc;
  --app-codesecure: #4ade80;
  --app-waassecure: #f472b6;
  --app-threatsecure: #f87171;
  --app-graphsecure: #818cf8;
  --app-netsecure: #22d3ee;
  --app-aisecure: #fdba74;
  --app-supplysecure: #9ca3af;
  --app-policysecure: #facc15;
  --app-compliancesecure: #2dd4bf;
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --bg: #0b0b0c;
    --bg-elevated: #141417;
    --ink-strong: #f2f1ee;
    --ink: #e2e1dc;
    --muted: #b4b3ae;
    --faint: #85858e;
    --line: #26262b;
    --line-strong: #85858e;
    --invert-bg: #f2f1ee;
    --invert-fg: #0b0b0c;
    --accent-ink: #ff6b35;
  }
}

*, *::before, *::after {
  box-sizing: border-box;
}

body {
  margin: 0;
  background-color: var(--bg);
  color: var(--ink);
  font-family: var(--font-sans);
  font-size: var(--text-body);
  line-height: 1.55;
  font-variant-numeric: tabular-nums;
  -webkit-font-smoothing: antialiased;
}

/* Mandatory Visible Keyboard Focus Indicator (R-32) */
:focus-visible {
  outline: 2px solid var(--accent-ink);
  outline-offset: 2px;
}

/* Architectural HUD Label (getartcraft.com signature) */
.hud-label {
  font-family: var(--font-mono);
  font-size: var(--text-hud);
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  line-height: 1;
}

/* Precision Crosshair Tick Marks at Grid Intersections */
.tick {
  position: absolute;
  width: 11px;
  height: 11px;
  pointer-events: none;
}
.tick::before,
.tick::after {
  content: "";
  position: absolute;
  background-color: var(--line-strong);
}
.tick::before {
  top: 5px;
  left: 0;
  width: 11px;
  height: 1px;
}
.tick::after {
  top: 0;
  left: 5px;
  width: 1px;
  height: 11px;
}

/* Primary & Secondary Square Invert CTAs */
.btn-cta-primary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  min-height: 48px;
  padding: 0 1.5rem;
  border-radius: 0;
  border: 1px solid var(--invert-bg);
  background-color: var(--invert-bg);
  color: var(--invert-fg);
  font-family: var(--font-mono);
  font-size: var(--text-hud);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  text-decoration: none;
  cursor: pointer;
  transition: opacity 150ms ease;
}
.btn-cta-primary:hover {
  opacity: 0.85;
}

.btn-cta-secondary {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  min-height: 48px;
  padding: 0 1.5rem;
  border-radius: 0;
  border: 1px solid var(--line-strong);
  background-color: var(--bg);
  color: var(--ink-strong);
  font-family: var(--font-mono);
  font-size: var(--text-hud);
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.12em;
  text-decoration: none;
  cursor: pointer;
  transition: background-color 150ms ease, color 150ms ease, border-color 150ms ease;
}
.btn-cta-secondary:hover {
  background-color: var(--invert-bg);
  color: var(--invert-fg);
  border-color: var(--invert-bg);
}
```

---

## 3. Shared Rust UI Foundation (`crates/cloudsecure-ui`)

`crates/cloudsecure-ui` provides the native `egui` + `wgpu` implementation of `DESIGN.md`:

```rust
// crates/cloudsecure-ui/src/theme.rs
use egui::{Color32, CornerRadius, Stroke, Style, Visuals};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ThemePreference {
    System,
    Light,
    Dark,
}

#[derive(Debug, Clone, Copy)]
pub struct SecurePalette {
    pub bg: Color32,
    pub bg_elevated: Color32,
    pub ink_strong: Color32,
    pub ink: Color32,
    pub muted: Color32,
    pub faint: Color32,
    pub line: Color32,
    pub line_strong: Color32,
    pub invert_bg: Color32,
    pub invert_fg: Color32,
    pub accent_ink: Color32,
    pub sev_critical: Color32,
    pub sev_high: Color32,
    pub sev_medium: Color32,
    pub sev_low: Color32,
    pub sev_pass: Color32,
}

impl SecurePalette {
    pub const LIGHT: Self = Self {
        bg: Color32::from_rgb(0xF2, 0xF1, 0xEE),
        bg_elevated: Color32::from_rgb(0xE6, 0xE4, 0xDF),
        ink_strong: Color32::from_rgb(0x0B, 0x0B, 0x0C),
        ink: Color32::from_rgb(0x1C, 0x1C, 0x1E),
        muted: Color32::from_rgb(0x4A, 0x4A, 0x46),
        faint: Color32::from_rgb(0x6B, 0x6A, 0x65),
        line: Color32::from_rgb(0xC8, 0xC6, 0xC0),
        line_strong: Color32::from_rgb(0x6B, 0x6A, 0x65),
        invert_bg: Color32::from_rgb(0x0B, 0x0B, 0x0C),
        invert_fg: Color32::from_rgb(0xF2, 0xF1, 0xEE),
        accent_ink: Color32::from_rgb(0xB7, 0x41, 0x0E),
        sev_critical: Color32::from_rgb(0xA8, 0x1E, 0x23),
        sev_high: Color32::from_rgb(0x94, 0x48, 0x00),
        sev_medium: Color32::from_rgb(0x6E, 0x56, 0x00),
        sev_low: Color32::from_rgb(0x1D, 0x4E, 0xD8),
        sev_pass: Color32::from_rgb(0x1B, 0x65, 0x35),
    };

    pub const DARK: Self = Self {
        bg: Color32::from_rgb(0x0B, 0x0B, 0x0C),
        bg_elevated: Color32::from_rgb(0x14, 0x14, 0x17),
        ink_strong: Color32::from_rgb(0xF2, 0xF1, 0xEE),
        ink: Color32::from_rgb(0xE2, 0xE1, 0xDC),
        muted: Color32::from_rgb(0xB4, 0xB3, 0xAE),
        faint: Color32::from_rgb(0x85, 0x85, 0x8E),
        line: Color32::from_rgb(0x26, 0x26, 0x2B),
        line_strong: Color32::from_rgb(0x85, 0x85, 0x8E),
        invert_bg: Color32::from_rgb(0xF2, 0xF1, 0xEE),
        invert_fg: Color32::from_rgb(0x0B, 0x0B, 0x0C),
        accent_ink: Color32::from_rgb(0xFF, 0x6B, 0x35),
        sev_critical: Color32::from_rgb(0xFF, 0x6B, 0x6B),
        sev_high: Color32::from_rgb(0xFF, 0xB3, 0x47),
        sev_medium: Color32::from_rgb(0xFA, 0xCC, 0x15),
        sev_low: Color32::from_rgb(0x60, 0xA5, 0xFA),
        sev_pass: Color32::from_rgb(0x4A, 0xDE, 0x80),
    };
}
```

### Shared `cloudsecure-ui` Widgets
1. `HudTopBar`: Renders the app's geometric SVG mark in `app_ink`, app title, CNAPP pillar badge, interactive RQL command bar, Light/Dark/System theme toggle, Locale selector, and Command Palette trigger (`Cmd+K` / `Ctrl+K`).
2. `DataViewContainer<T>`: Enforces `antislop` **R-27** at the type level by taking an enum `DataState<T> { Empty { reason, action_label, on_action }, Loading { stage, completed, total }, Error { code, message, recovery_label, on_recover }, Loaded(T) }`. It is impossible for a developer to render a data view without supplying the Empty, Loading, and Error states.
3. `SeverityBadge`: Renders both the geometric shape glyph (`[!]`, `[/!\]`, `[<>]`, `[i]`, `[OK]`) and the text label (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `PASS`) with `SecurePalette` WCAG AA colors.
4. `VirtualizedFindingTable`: Renders 100,000+ security findings at 60 FPS using `egui_extras::TableBuilder` with keyboard row navigation (`Up`/`Down`/`Enter`).
5. `SecurityGraphViewport`: Interactive `wgpu`/painter node-link canvas with pan, zoom, node selection, blast-radius highlighting, and "What-If" edge toggling.
6. `RemediationDiffView`: Side-by-side and unified diff renderer for Terraform HCL, Kubernetes YAML, IAM JSON, and CLI remediation patches with 1-click copy/export.

---

## 4. RQL Engine Grammar & AST (`crates/cloudsecure-rql`)

### EBNF Grammar Supported Across All Apps
```ebnf
query          ::= family_clause "from" source_clause ("where" expr)? ("limit" INT)? ;
family_clause  ::= "config" | "network" | "event" | "iam" | "data" ;
source_clause  ::= "cloud.resource" | "vpc.flow_record" | "cloud.audit_logs"
                 | "cloud.entitlements" | "cloud.data_store" ;
expr           ::= or_expr ;
or_expr        ::= and_expr ("or" and_expr)* ;
and_expr       ::= not_expr ("and" not_expr)* ;
not_expr       ::= "not"? primary_expr ;
primary_expr   ::= comparison | "(" expr ")" ;
comparison     ::= field_path comparator value_expr ;
comparator     ::= "=" | "!=" | ">" | ">=" | "<" | "<="
                 | "in" | "not in" | "contains" | "starts with"
                 | "is true" | "is false" | "is empty" | "is not empty" ;
field_path     ::= IDENT ("." IDENT | "[" INT "]")* ;
value_expr     ::= STRING | NUMBER | BOOL | "(" value_list ")" ;
value_list     ::= value_expr ("," value_expr)* ;
```

---

## 5. CI-Enforced Performance & Footprint Budgets

| Metric | Target Budget | Verification Command |
|---|---|---|
| Native Cold Start to First Frame | `< 400 ms` | `cargo test --release -p cloudsecure-testkit -- bench_startup` |
| Native Idle Memory (RSS) | `< 80 MB` | Measured after 60s idle in `cargo xtask verify` |
| Native Binary Size (Stripped) | `< 15 MB` per app | `ls -lh target/release/<app>` check in `xtask` |
| WebAssembly Bundle Size (`.wasm.gz`) | `< 900 KB` per app | `cargo xtask build-wasm` size gate |
| RQL Evaluation Latency (10k resources) | `< 15 ms` p95 | `cargo test --release -p cloudsecure-rql` |
| Unsafe Rust Usage | `0` occurrences | `[workspace.lints.rust] unsafe_code = "forbid"` |
