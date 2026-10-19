# CloudSecure Web Portal (`getartcraft.com` Replica) & GitHub Program Specification

> **Authored by**: `agency-ux-architect`, `agency-frontend-developer`, `agency-devops-automator`, `agency-git-workflow-master`  
> **Scope**: Complete specification for `web/cloudsecure-site` (replicating `getartcraft.com` and `getartcraft.com/apps` in Rust) and the automated GitHub repository/release program (`xtask` + `.github/workflows/`).

---

## 1. Web Portal Architecture (`web/cloudsecure-site`)

### 1.1 Pure Rust Web Stack
To satisfy the user's requirement that **all apps and tooling are built in Rust**:
- **Server & Static Site Generator**: `web/cloudsecure-site` is a Rust crate built with **`axum` (0.8)** + **`maud` / `askama` type-safe compile-time HTML templates** + **embedded static asset bundler**.
- **Dual Execution Mode**:
  1. `cargo run -p cloudsecure-site -- serve --port 8080`: Runs a blazing-fast local/production `axum` HTTP server serving all routes, static assets, and interactive `/api/rql/evaluate` endpoints (backed directly by `crates/cloudsecure-rql` and `crates/cloudsecure-graph`).
  2. `cargo run -p cloudsecure-site -- build-static --out ./dist-web`: Generates a 100% static HTML + CSS + Wasm bundle deployable to GitHub Pages (`cloudsecure.github.io`) or Cloudflare Pages.
- **Interactive Browser Wasm Apps**: Each of the 14 `egui` applications compiles to WebAssembly via `trunk` (`cargo xtask build-wasm`) and mounts directly inside `/wasm/<app-slug>/index.html`, linked from every app card's `Launch Web App` button.

### 1.2 Structural Replication of `getartcraft.com` & `getartcraft.com/apps`
Inspecting the live DOM of `getartcraft.com` and `getartcraft.com/apps` reveals a highly distinctive architectural design system that `cloudsecure-site` replicates faithfully while adapting every word of content to the 13 CloudSecure CNAPP products:

1. **Sticky HUD Top Navigation Bar (`<nav id="site-nav">`)**:
   - Height: `48px` (`h-12`), `sticky top-0 left-0 z-50 w-full border-b border-line bg-bg/95 backdrop-blur-sm`.
   - Left Cluster:
     - Brand Logo cell (`border-r border-line px-5`): Geometric CloudSecure shield-prism SVG + `CLOUDSECURE` wordmark.
     - Horizontal HUD Links (`font-mono uppercase tracking-[0.12em] text-[11px]`):
       - `Home` (`/`)
       - `Posture (CSPM)` (`/apps/posturesecure`)
       - `Data (DSPM)` (`/apps/datasecure`)
       - `Workloads (CWPP)` (`/apps/workloadsecure`)
       - `RQL Studio` (`/rql`)
       - `Download` (`/download`)
       - `Docs` (`/docs`)
       - Separated by `border-l border-line`: **`Secure Apps (13)`** (`/apps`, highlighted with `bg-invert-bg text-invert-fg` when active).
   - Right Cluster:
     - `GitHub` icon cell (`w-12 border-l border-line`, links to `https://github.com/cloudsecure`).
     - `Theme Toggle` button (`w-12 border-l border-line`, switches `light` / `dark` / `system`, updates `document.documentElement.setAttribute("data-theme", t)` and `localStorage.setItem("cloudsecure-theme", t)` before first paint via inline `<head>` script).
     - Primary CTA (`h-full border-l border-line px-5 bg-invert-bg text-invert-fg font-mono font-bold uppercase tracking-[0.12em] text-[11px]`): **`Launch RQL Studio`** (`/rql`).
     - Mobile Menu Button (`< 960px`): Labeled `Menu` toggle (`min-w-[48px] h-12`) opening an accessible keyboard-trapped drawer closable with `Escape` (R-03, R-32).

2. **Central Architectural Column & Crosshair Ticks**:
   - Every main section sits inside `mx-auto max-w-[1280px] border-x border-line relative`.
   - Top-left and top-right intersections render precision `5px` crosshair ticks (`<span aria-hidden="true" class="tick tick-half -top-[5px] -left-[6px]"></span>`).
   - Sticky Section Eyebrow Bar (`sticky top-12 z-30 border-y border-line bg-bg/85 backdrop-blur-md px-6 py-3 md:px-10 flex items-center justify-between`):
     - Left: `<p class="hud-label text-muted"><span class="text-faint">01</span> / CloudSecure Security Suite</p>`
     - Right: `<p class="hud-label text-faint">Thirteen apps · Open source · Pure Rust</p>`

---

## 2. Complete Route Map & Page Specifications (Zero Dead Links per R-24, R-26)

Every link in the navbar, hero, app cards, and footer resolves to one of these real, rendered routes:

### Route 1: `/` (Home: The Open-Source Rust CNAPP Studio)
- **Section `01 / Overview`**:
  - Headline: `"Cloud-to-Code Security, Rebuilt in Pure Rust."`
  - Subheadline: `"Agentless CSPM, sensitive data classification (DSPM), container & runtime defense (CWPP), IAM least-privilege graphs (CIEM), Open-source IaC static scanning (ASPM), layer-7 API security (WAAS), and Cloud Detection & Response (CDR). Thirteen native, open-source apps that run offline on your workstation, in CI, or in the browser via WebAssembly."`
  - Primary CTAs:
    - `[Download LauncherSecure]` (scrolls to OS installer matrix or triggers direct release download)
    - `[Explore All 13 Apps]` (links to `/apps`)
    - `[Open Interactive RQL Studio]` (links to `/rql`)
  - Interactive Hero Workbench: A live, functional RQL & Attack Path inspector wired to `/api/rql/evaluate` (and pre-loaded with the bundled 420-resource multi-cloud corpus) where visitors can click real RQL queries, inspect the resulting breach path, and view the generated Terraform remediation diff right on the homepage.
- **Section `02 / Why Pure Rust`**:
  - Technical comparison table (Memory footprint, Cold start time, Binary size, Offline capability, Agent/MCP protocol support) grounding the engineering architecture with verifiable workspace benchmarks.
- **Section `03 / Flagship Pillars`**:
  - Deep-dive interactive previews of the core pillars requested by the user: **CSPM (`PostureSecure`)**, **DSPM (`DataSecure`)**, **CWPP (`WorkloadSecure`)**, **CIEM (`IdentitySecure`)**, **ASPM (`CodeSecure`)**, **WAAS (`WaasSecure`)**, and **CDR (`ThreatSecure`)**.
- **Section `04 / Built for Agents (CLI + JSON-RPC + MCP)`**:
  - Demonstrates the 4-way control surface (`egui` UI, `<app>-cli`, JSON-RPC stdio, and MCP tool calls) with copyable command blocks.

### Route 2: `/apps` (The 13-App Catalog, Replicating `getartcraft.com/apps`)
- **Sticky Eyebrow `01 / CloudSecure Apps`**: `"Thirteen apps · Open source · Pure Rust"`
- **Hero Block**:
  - H1: `"Thirteen security apps. One unified architecture."` (with `unified architecture` styled in `var(--accent-ink)` and `Instrument Serif`).
  - Lead paragraph: `"Posture management (CSPM), data security (DSPM), workload protection (CWPP), identity entitlements (CIEM), IaC & code security (ASPM), web/API firewall (WAAS), cloud threat detection (CDR), attack path graphs, zero-trust network segmentation (CNS), AI security posture (AI-SPM), supply chain attestation, RQL policy authoring, and compliance audit bundles. Native, open-source apps built in Rust and free to use."`
  - CTA Row: `[Download Launcher]`, `[Browse on GitHub]`, `[Launch RQL Playground]`, plus functional `[Copy Link]` share bar with `aria-live="polite"` feedback.
  - Recommendation Note: `"Recommended: LauncherSecure installs every app below, verifies SHA-256 & Ed25519 release signatures, and keeps them all up to date."`
- **Sticky Eyebrow `02 / CNAPP Suite Directory`**:
  - Interactive filter bar by CNAPP Pillar (`All (13)`, `Posture & Data`, `Workloads & Network`, `Identity & Attack Graph`, `Shift-Left & Supply Chain`, `SecOps & Governance`) + Search input.
  - **The 13 Application Showcase Sections**: Each app renders in its own architectural grid bay featuring:
    - Index number (`01` through `13`), geometric SVG icon in `--app-ink`, App Name, CNAPP capability badge (`CSPM`, `DSPM`, `CWPP`, etc.), version tag (`v0.1.0`), and license (`MIT / Apache-2.0`).
    - Specific engineering description of what the Rust engine parses and solves.
    - Deterministic screenshot/preview of the app's `egui` workbench.
    - Action row: `[Open App Spec (/apps/<slug>)]`, `[Launch in Browser (Wasm)]`, `[Download CLI & Desktop]`.

### Route 3: `/apps/:slug` (13 Individual Application Deep-Dive Pages)
Generated for all 13 slugs (`posturesecure`, `datasecure`, `workloadsecure`, `identitysecure`, `codesecure`, `waassecure`, `threatsecure`, `graphsecure`, `netsecure`, `aisecure`, `supplysecure`, `policysecure`, `compliancesecure`):
- App Hero with `--app-ink` accent, live `[Launch in Browser (Wasm)]` button, and OS-specific installer links.
- **Interactive Workbench Preview / Wasm Embed**.
- **Feature Breakdown Grid** (4 key engineering capabilities, matching `photocraft` README depth).
- **Sample RQL Queries & Policy Rules** specific to that app.
- **CLI & MCP Server Reference** (exact flags, JSON-RPC schema, and MCP tool signatures for that app).

### Route 4: `/rql` (Interactive RQL & Attack Path Playground)
- Live browser workbench powered by `cloudsecure-rql` and `cloudsecure-graph` where users can select from 15 preset RQL queries across `config`, `network`, `event`, `iam`, and `data` (or type custom RQL), view the parsed AST, inspect matching cloud resources, and copy the generated Terraform/CLI remediation patch. Includes explicit Empty, Loading, and Syntax Error states (R-27).

### Route 5: `/download` (Platform & Architecture Installer Matrix)
- Replicates `getartcraft.com/download` + `craft-launcher` installation table:
  - Primary card for **LauncherSecure** (`macOS Universal .dmg`, `Windows .msi & Portable .zip`, `Linux .deb / .rpm / .AppImage / Flatpak`, `FreeBSD .pkg`).
  - Full 13-app x 6-platform release matrix table with SHA-256 checksum copy buttons and `cargo install --git` source build instructions.

### Route 6: `/docs` (Architecture, RQL Grammar & MCP Agent Guide)
- Complete technical documentation covering the Hexagonal Rust workspace, RQL BNF grammar, `.csec` snapshot format, and how to connect Claude / Gemini / Cursor to any CloudSecure app via `--mcp`.

### Routes 7, 8, 9: `/security`, `/privacy`, `/terms` (Trust & Governance Pages per R-38)
- `/security`: Vulnerability disclosure policy, `unsafe_code = "forbid"` guarantee, `SecretRedactor` zeroization architecture, and Ed25519 release signing keys.
- `/privacy`: Zero-telemetry guarantee (100% local execution, no analytics beacons, no cloud phone-home).
- `/terms`: Dual `MIT OR Apache-2.0` open-source license terms and non-affiliation disclaimer.

---

## 3. GitHub Repository & Release Automation Program

### 3.1 Repository Strategy: Unified Workspace + Automated Multi-Repo Mirroring
To give developers both **single-command workspace ergonomics** (`cargo test --workspace`) and **ArtCraft-style individual GitHub repositories** (`github.com/<org>/launchersecure`, `github.com/<org>/posturesecure`, `github.com/<org>/datasecure`, etc.):
1. **Primary Monorepo (`cloudsecure`)**: Contains the complete Cargo workspace (`crates/*`, `apps/*`, `web/cloudsecure-site`, `xtask`, `.github/workflows/*`).
2. **Automated GitHub Provisioner (`cargo xtask github-init`)**:
   - Uses the GitHub CLI (`gh`) to create/configure either a single monorepo or the full 15-repo organization layout (`cloudsecure-libs`, `launchersecure`, `cloudsecure-site`, plus the 13 app repos), set repo descriptions, topics (`rust`, `cnapp`, `cspm`, `dspm`, `cwpp`, `ciem`, `aspm`, `egui`, `webassembly`, `mcp`), branch protection rules on `main`, and GitHub Pages configuration.

### 3.2 `xtask` Build & Packaging Subcommands (`xtask/src/main.rs`)
`cargo xtask` provides deterministic, zero-shell-script automation in pure Rust:
- `cargo xtask verify`: Runs `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and `contrast-check.py` token validation.
- `cargo xtask build-wasm`: Compiles `launchersecure` and the 13 apps to `wasm32-unknown-unknown`, runs `wasm-opt -Oz --strip-debug --dce`, verifies each compressed `.wasm` bundle is `< 900 KB`, and stages them into `web/cloudsecure-site/static/wasm/`.
- `cargo xtask render-screenshots`: Drives all 14 `egui` apps offscreen using `egui_kittest` in Light and Dark modes against the bundled cloud fixture corpus and writes deterministic PNG screenshots to `web/cloudsecure-site/static/images/apps/`.
- `cargo xtask package --target <triple>`: Packages native release binaries into platform bundles (`.app`/`.dmg` layout on macOS, `.msi`/`.zip` on Windows, `.deb`/`.rpm`/`.AppImage` on Linux) and generates `manifest.json` with SHA-256 digests and Ed25519 signatures.
- `cargo xtask github-init --org <org-name> [--dry-run]`: Generates and optionally executes `gh repo create` and release publishing commands.

### 3.3 GitHub Actions CI/CD Workflows (`.github/workflows/`)
1. **`.github/workflows/ci.yml`**:
   - Triggers on every push and PR to `main`.
   - Jobs: `fmt-and-clippy` (`unsafe_code = "forbid"`), `unit-and-proptest`, `wasm-size-gate`, `web-playwright-qa` (starts `cloudsecure-site`, runs Playwright across Desktop/Tablet/Mobile in Light/Dark mode, fails on any console error or broken link), and `security-audit` (`cargo audit` + `gitleaks`).
2. **`.github/workflows/release.yml`**:
   - Triggers on `v*.*.*` tags.
   - Builds across matrix (`macos-14` Apple Silicon, `macos-13` Intel, `windows-2022`, `ubuntu-22.04`), signs & notarizes when certificates are configured in GitHub Secrets, generates `SHA256SUMS` and `manifest.json`, and publishes to GitHub Releases.
3. **`.github/workflows/pages.yml`**:
   - Builds `cargo xtask build-wasm` + `cargo run -p cloudsecure-site -- build-static --out ./dist-web` and deploys to GitHub Pages.
