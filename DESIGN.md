# CloudSecure Design System & Visual Direction (`DESIGN.md`)

## 1. Design Read & Identity Direction

Reading this as: Open-source CNAPP security desktop and web application suite catalog and documentation portal for cloud security engineers, SecOps analysts, and DevSecOps architects, in a precision technical-manual HUD grid language inspired by `getartcraft.com`, dial `ENERGY 2 / RHYTHM 2 / MOTION 2`.

- **Brand Name**: CloudSecure (`cloudsecure.dev` / GitHub Organization: `cloudsecure`)
- **Tagline**: Thirteen security apps. One unified architecture. Rebuilt in pure Rust.
- **Core Identity**: Clean-room, open-source, 100% pure Rust reimplementation of the complete Enterprise Multi-Cloud CNAPP (CSPM, DSPM, CWPP, CIEM, ASPM, WAAS, CDR, Attack Path, CNS, AI-SPM, Supply Chain, Policy-as-Code, and Executive Compliance) portfolio across native desktop (`egui` + `eframe` + `wgpu` on macOS, Windows, Linux, FreeBSD), headless CLI, JSON-RPC automation, Model Context Protocol (MCP) servers, and browser WebAssembly (`trunk`).
- **Disclaimer Requirement**: Every footer and README states clearly: *"CloudSecure is an independent, clean-room open-source security tool suite written in Rust. It is not affiliated with, endorsed by, or sponsored by enterprise CNAPP Networks, Inc."*

---

## 2. Three Dials & Five Levers (Antislop Part 3)

### Three Dials
| Dial | Setting | Level Name | Concrete Behavioral Rule |
|---|---|---|---|
| **ENERGY** | `2` | **Balanced** | High-contrast editorial typography paired with exposed `1px` technical grid hairlines and precision HUD labels. No neon cyberpunk glows, no rainbow gradients, and no sterile unstyled defaults. |
| **RHYTHM** | `2` | **Consistent with structural breaks** | Sections are anchored by sticky numbered HUD eyebrows (`01 / Suite Catalog`, `02 / RQL Engine`, `03 / Architecture`, `04 / Agent & MCP Control`, `05 / Platform Matrix`) inside a `1280px` bordered column, alternating between full-width interactive workbench previews, asymmetric 2-column technical breakdowns, and a dense 13-app specification catalog. |
| **MOTION** | `2` | **Scroll-reveal & state transitions** | Instant `150ms` color-invert hover states (`bg-invert-bg text-invert-fg`), smooth layout reflow between Grid and Table views in the launcher, and deterministic `60fps` `wgpu` canvas pan/zoom in the apps. Respects `prefers-reduced-motion: reduce`. Zero endless pulsing dots or floating loops. |

### Five Levers
1. **One Focal Point Per Screen**:
   - Web Home (`/`): The interactive multi-cloud Attack Path & RQL live workbench preview.
   - Web Suite Catalog (`/apps`): The 13-app interactive specification matrix with live Wasm launch triggers and the primary `Download Launcher` CTA.
   - Native/Wasm Launcher (`launchersecure`): The 13-app status grid/table showing installed version, SHA-256 verification badge, and one-click `Install` / `Open` / `Update` action.
   - Individual CNAPP Apps: The central `wgpu`/table inspection canvas (e.g., RQL query results in `PostureSecure`, sensitive data classification map in `DataSecure`, blast-radius graph in `GraphSecure`).
2. **Hierarchical Contrast**:
   - Display headlines use `Archivo` / `Instrument Serif` with tight tracking (`-0.035em`).
   - Technical coordinates, section indices (`01 / ...`), SHA-256 hashes, RQL queries, and CTAs use `Geist Mono` (`11px` uppercase with `0.12em` tracking for HUD labels; `13px` normal case for RQL/code).
   - Body copy and remediation descriptions use `Inter` (`16px` web, `13.5px` desktop `egui`).
3. **Whitespace as Structure**:
   - Exposed `1px` structural grid lines (`--line`) divide the viewport into architectural bays rather than floating cards in empty space.
4. **One Deliberate Accent**:
   - Primary brand accent is **Rust Oxide** (`#B7410E` in Light Mode, `#FF6B35` in Dark Mode), used strictly for the active product highlight word, active focus ring, and primary severity/action focal point. Each of the 13 apps also defines one semantic `--app-ink` token used only within that app's header badge and active tool indicator.
5. **Identity Motif**:
   - Exposed `1px` architectural hairlines (`border-line`), precision `5px` crosshair tick marks (`tick tick-half`) at structural grid intersections, sticky numbered HUD section bars (`01 / ...`), and square-cornered (`rounded-none`) instant-invert buttons.

---

## 3. WCAG AA Verified Color System (`contrast-check.py` Certified)

All color pairings below have been mathematically verified using `/Users/sadiqadeyanju/.gemini/config/plugins/antislop/skills/antislop-human/contrast-check.py` to meet or exceed WCAG 2.1 AA (`4.5:1` for normal text, `3.0:1` for large text and non-text interactive boundaries).

### Core Theme Palette (Light Mode: Technical Paper / Dark Mode: Carbon SOC)

| Semantic Token | Light Mode Hex | Light Contrast vs `--bg` | Dark Mode Hex | Dark Contrast vs `--bg` | Purpose & Usage |
|---|---|---|---|---|---|
| `--bg` | `#F2F1EE` | Baseline | `#0B0B0C` | Baseline | Primary page and `egui` central canvas background |
| `--bg-elevated` | `#E6E4DF` | `1.12:1` (surface) | `#141417` | `1.15:1` (surface) | Secondary panel, sidebar, and table header surface |
| `--ink-strong` | `#0B0B0C` | **17.42:1 (PASS)** | `#F2F1EE` | **17.42:1 (PASS)** | Primary headings, active values, primary body text |
| `--ink` | `#1C1C1E` | **15.10:1 (PASS)** | `#E2E1DC` | **14.85:1 (PASS)** | Standard body copy and table cell text |
| `--muted` | `#4A4A46` | **7.88:1 (PASS)** | `#B4B3AE` | **9.37:1 (PASS)** | Secondary descriptions, metadata, inactive tabs |
| `--faint` | `#6B6A65` | **4.80:1 (PASS)** | `#85858E` | **5.38:1 (PASS)** | Section index numbers (`01 /`), timestamps, subtle captions |
| `--line` | `#C8C6C0` | Structural divider | `#26262B` | Structural divider | Decorative hairline grid dividers (`1px`) |
| `--line-strong` | `#6B6A65` | **4.80:1 (PASS >= 3:1)** | `#85858E` | **5.38:1 (PASS >= 3:1)** | Interactive button/input borders and focus boundaries |
| `--invert-bg` | `#0B0B0C` | **17.42:1 (PASS)** | `#F2F1EE` | **17.42:1 (PASS)** | High-contrast primary CTA and hover invert fill |
| `--invert-fg` | `#F2F1EE` | **17.42:1 (PASS)** | `#0B0B0C` | **17.42:1 (PASS)** | Text inside inverted CTAs and active nav pills |
| `--accent-ink` | `#B7410E` | **4.92:1 (PASS)** | `#FF6B35` | **6.94:1 (PASS)** | Rust Oxide primary brand accent and `:focus-visible` outline |

### Security Severity Tokens (Paired with Mandatory Text + Icon Labels per R-25 & Human Skill)

Every severity indicator MUST render both an explicit text label (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `PASS`) and a distinct geometric shape icon (Octagon, Triangle, Diamond, Circle, Check-Square) so status is never communicated by color alone.

| Severity Level | Light Mode Text/Icon Hex | Light Contrast vs `#F2F1EE` | Dark Mode Text/Icon Hex | Dark Contrast vs `#0B0B0C` | Geometric Glyph |
|---|---|---|---|---|---|
| **CRITICAL (P0)** | `#A81E23` | **6.47:1 (PASS)** | `#FF6B6B` | **7.09:1 (PASS)** | Filled Octagon `[!]` |
| **HIGH (P1)** | `#944800` | **5.84:1 (PASS)** | `#FFB347` | **11.05:1 (PASS)** | Upward Triangle `[/!\]` |
| **MEDIUM (P2)** | `#6E5600` | **5.41:1 (PASS)** | `#FACC15` | **12.75:1 (PASS)** | Diamond `[<>]` |
| **LOW / INFO (P3)** | `#1D4ED8` | **5.92:1 (PASS)** | `#60A5FA` | **7.86:1 (PASS)** | Circle `[i]` |
| **COMPLIANT / PASS** | `#1B6535` | **6.28:1 (PASS)** | `#4ADE80` | **11.29:1 (PASS)** | Check Square `[OK]` |

### Per-App Semantic Identity Tokens (`--app-ink`)

Each of the 13 CloudSecure applications has a dedicated `--app-ink` accent token (all verified >= `4.5:1` against `--bg` in both themes) used exclusively for that app's geometric mark and active header indicator:

| App # | App Name | CNAPP Security Pillar | Light `--app-ink` | Dark `--app-ink` | Geometric Icon Motif |
|---|---|---|---|---|---|
| `01` | **PostureSecure** | CSPM (Posture & Compliance) | `#0F52BA` | `#5C9DFF` | Isometric Shield Grid |
| `02` | **DataSecure** | DSPM (Data Classification & DDR) | `#0D6E52` | `#34D399` | Layered Cylinder Vault |
| `03` | **WorkloadSecure** | CWPP (Containers, VMs, Serverless) | `#8B3A0E` | `#FB923C` | Hexagonal Pod Matrix |
| `04` | **IdentitySecure** | CIEM (IAM & Least Privilege) | `#6B21A8` | `#C084FC` | Key-Graph Node |
| `05` | **CodeSecure** | ASPM & IaC (IaC / SCA / SBOM) | `#1E5631` | `#4ADE80` | AST Brackets `</>` |
| `06` | **WaasSecure** | WAAS (API & Layer-7 Firewall) | `#9D174D` | `#F472B6` | Wave Inspection Gate |
| `07` | **ThreatSecure** | CDR (Cloud Detection & Response) | `#A81E23` | `#F87171` | Radar Pulse Crosshair |
| `08` | **GraphSecure** | Attack Path & Infinity Graph | `#4338CA` | `#818CF8` | Directed Acyclic Graph |
| `09` | **NetSecure** | CNS (Zero-Trust Microsegmentation) | `#0E606B` | `#22D3EE` | Segmented Mesh Topology |
| `10` | **AiSecure** | AI-SPM (Model & Pipeline Security) | `#7C2D12` | `#FDBA74` | Tensor Lattice |
| `11` | **SupplySecure** | Supply Chain & SLSA Provenance | `#374151` | `#9CA3AF` | Interlocking Chain Link |
| `12` | **PolicySecure** | RQL & Policy-as-Code Studio | `#854D0E` | `#FACC15` | Rule Scales & Balance |
| `13` | **ComplianceSecure** | Executive Command & Audit Bundles | `#115E59` | `#2DD4BF` | Telemetry Ledger |

---

## 4. Typography & Scale

### Font Roster & Written Purpose-Gate Justifications (R-06)
1. **Display (`--font-display`)**: `'Archivo'`, fallback `'Inter'`, system sans.
   - *Written Reason (R-06)*: Chosen to match `getartcraft.com`'s grotesque architectural display headlines with tight `-0.035em` letter-spacing for high-density technical legibility.
2. **Editorial Accent (`--font-serif`)**: `'Instrument Serif'`, fallback `Georgia, serif`.
   - *Written Reason (R-06)*: Used selectively on the single emphasized noun in flagship hero headlines (e.g., *"Thirteen security apps. One unified architecture."*) to mirror `getartcraft.com`'s human craftsmanship contrast against the technical HUD grid.
3. **UI & Body (`--font-sans`)**: `'Inter'`, fallback system-ui.
   - *Written Reason (R-06)*: Provides tabular numerals (`font-variant-numeric: tabular-nums`) and high x-height legibility at `13px-16px` inside dense security tables, CVE matrices, and compliance trees.
4. **Technical HUD & RQL (`--font-mono`)**: `'Geist Mono'`, fallback `'JetBrains Mono', monospace`.
   - *Written Reason (R-06)*: Used strictly for RQL queries, SHA-256 digests, IAM ARNs, CVE identifiers, CLI flags, and compact `11px` HUD coordinate labels where fixed-width character alignment prevents misreading security identifiers. Never used for large hero headings.

### Fluid Type Scale (Web CSS & Responsive Reflow per R-03, R-35)
- `--text-hero`: `clamp(2.25rem, 4.5vw + 1rem, 4.25rem)` (`line-height: 1.02`, `letter-spacing: -0.035em`)
- `--text-h1`: `clamp(1.875rem, 3vw + 0.75rem, 3.25rem)` (`line-height: 1.06`, `letter-spacing: -0.03em`)
- `--text-h2`: `clamp(1.5rem, 2vw + 0.5rem, 2.25rem)` (`line-height: 1.15`, `letter-spacing: -0.02em`)
- `--text-h3`: `clamp(1.125rem, 1.2vw + 0.5rem, 1.5rem)` (`line-height: 1.25`)
- `--text-body-lg`: `clamp(1.0rem, 0.4vw + 0.9rem, 1.125rem)` (`line-height: 1.6`)
- `--text-body`: `1rem` (`16px`, `line-height: 1.55`)
- `--text-hud`: `0.6875rem` (`11px`, `font-family: var(--font-mono)`, `text-transform: uppercase`, `letter-spacing: 0.12em`)

---

## 5. Layout, Breakpoints & Component Rules

### Multi-State Responsive Reflow (R-03, `antislop-layoutmobile`)
The layout defines **four explicit content-driven states** (never a 2-state desktop squeeze):
1. **Narrow Mobile (`< 640px`)**:
   - Single-column reflow.
   - Top navbar keeps Logo, Theme Toggle (`48x48px`), primary `Launch RQL` CTA, and labeled `Menu` button (`48x48px` with visible text + icon, never a bare unlabeled hamburger).
   - Section padding drops to `24px` horizontal, `40px` vertical.
   - App catalog cards stack in 1 column; complex comparison tables switch to prioritized card rows showing App Name, Module, Status, and Primary Install/Launch CTA.
2. **Tablet / Compact (`640px - 959px`)**:
   - 2-column grid (`grid-template-columns: repeat(2, minmax(0, 1fr))`) for the 13-app catalog.
   - Workbench previews stack the inspector drawer below the primary canvas.
3. **Small Laptop / Desktop (`960px - 1279px`)**:
   - 3-column app grid; full horizontal HUD navigation bar revealed; 2-column asymmetric technical feature breakdowns.
4. **Wide Studio (`>= 1280px`)**:
   - Central `max-w-[1280px]` architectural frame with exposed left/right `1px` borders (`border-x border-line`) and corner crosshair ticks (`tick tick-half`).

### Interactive Targets & Keyboard Navigation (R-03, R-26, R-32)
- Every interactive button, link, tab, theme toggle, and table sort header has a minimum hit area of `44x44px` on touch/mobile and `36px+` height with `>= 4px` spacing on desktop.
- `:focus-visible` renders a `2px solid var(--accent-ink)` outline with `2px` offset (`3:1+` contrast in both Light and Dark themes). `outline: none` without replacement is strictly forbidden.
- Every modal, command palette (`Cmd+K` / `Ctrl+K`), and mobile navigation drawer closes on `Escape` and traps focus cleanly.

### Mandatory UI States for All Data Views (R-27)
Every data view in `cloudsecure-site`, `launchersecure`, and all 13 Rust `egui` apps MUST implement three explicit, informative states:
1. **Empty State**: Explains *why* the view is empty and provides a single direct action button that populates it (e.g., *"No cloud posture snapshot loaded. Load the included AWS/GCP/Azure sample corpus or connect a read-only cloud profile to run 140+ CIS checks."* + `[Load Sample Corpus]` button).
2. **Loading State**: Displays deterministic progress with the specific stage name and item count (e.g., *"Evaluating 142 RQL posture rules against 1,280 cloud resources (64%)..."*), never an unlabeled spinner.
3. **Error State**: States the exact failure, error code, and recovery action (e.g., *"SHA-256 checksum mismatch on posturesecure-0.1.0-aarch64-apple-darwin.dmg (expected e3b0c44..., got 9f86d08...). Artifact quarantined."* + `[Retry Download]` / `[View Verification Log]`).

---

## 6. Design Contracts Per Surface (`agency-ui-finish-gate-reviewer`)

### Surface A: `cloudsecure-site` Marketing & Documentation Portal (`/` and `/apps`)
- **User + job**: Cloud security engineer or DevSecOps architect evaluating whether CloudSecure covers their enterprise CNAPP (CSPM, DSPM, CWPP, CIEM, ASPM, WAAS, CDR) workflows and downloading the native Rust launcher or testing an app in-browser via WebAssembly.
- **First-read object**: The headline *"Thirteen security apps. One unified architecture."* paired with the live interactive 13-app CNAPP matrix and the `Download Launcher` / `Launch in Browser (Wasm)` controls.
- **Primary action**: Download `LauncherSecure` for the user's detected OS/CPU, or launch any of the 13 apps directly in the browser Wasm workspace.
- **Density decision**: High-density technical specification layout (matching `getartcraft.com/apps`), avoiding fluffy SaaS marketing blocks.
- **Forbidden defaults**: No blue-to-purple gradients, no fake customer logo bars, no fabricated statistics (`99.9% uptime`, `10K+ enterprises`), no 3-tier SaaS pricing cards (the suite is 100% free and open-source under MIT/Apache-2.0), no generic 3-step "How It Works" cartoons, no dead footer links.

### Surface B: `launchersecure` (Native `egui` + WebAssembly App Manager)
- **User + job**: Security operator installing, updating, verifying checksums, and launching the 13 CloudSecure apps or switching between Grid and Table catalog views.
- **First-read object**: The 13-app catalog (with instant toggle between Card Grid View and Sortable Version/Checksum Table View, replicating `craft-launcher`).
- **Primary action**: One-click `Install`, `Update`, or `Open` on any of the 13 apps, with real SHA-256 verification status.
- **Density decision**: Compact studio utility (`egui` grid/table with instant search filter, category filter by CNAPP pillar, language selector, and light/dark/system theme selector).

### Surface C: The 13 CloudSecure Security Workbenches (`egui` + `wgpu`)
- **User + job**: Security engineer auditing cloud configs, classifying sensitive data stores, inspecting container layers, analyzing IAM privilege graphs, or running RQL queries.
- **First-read object**: The active RQL/policy command bar at the top and the central inspection canvas/table/graph showing prioritized findings with deterministic remediation diffs.
- **Primary action**: Execute an RQL query / scan against a target directory, container image, or cloud state snapshot, inspect the finding path, and export a deterministic remediation patch (Terraform/CLI/Rego/SARIF).
- **Density decision**: Compact professional IDE/workbench density (`13px` UI font, virtualized 100k-row tables, dockable left asset rail, center `wgpu` graph/table canvas, right remediation diff inspector, bottom JSON-RPC/MCP/RQL log console).

---

## 7. Antislop Purpose-Gate Ledger (R-01 to R-38 Written Justifications)

| Rule | Technique / Element | Written One-Line Purpose Justification |
|---|---|---|
| **R-01** | Subtle radial backdrop mask behind hero headline only | Improves text legibility over the interactive wireframe grid in `getartcraft.com` style; zero blue-purple gradients anywhere. |
| **R-04** | 13 bespoke geometric SVG/vector app marks + 5 severity shape glyphs | Each icon encodes a specific CNAPP security domain or WCAG non-color severity state; zero generic sparkle/magic/robot icons. |
| **R-06** | `Geist Mono` uppercase `11px` HUD labels & RQL syntax | Aligns fixed-width technical coordinates, SHA-256 hashes, ARNs, and RQL queries; headings remain in `Archivo`. |
| **R-07** | Exposed `1px` structural borders (`--line`) + `5px` corner crosshair ticks | Establishes the `getartcraft.com` architectural blueprint layout grid and visually separates dense multi-app catalog bays. |
| **R-08** | Downward install arrow (`arrow-down-to-line`) on `Download Launcher` only | Signals a direct binary file download action versus in-page navigation; secondary buttons carry no decorative arrows. |
| **R-09** | Module pillar tags (`CSPM`, `DSPM`, `CWPP`, `CIEM`, `ASPM`, `WAAS`, `CDR`) | Identifies which CNAPP capability each Rust app replaces; no "AI Powered", "New", or eyebrow pills duplicating the H1. |
| **R-10** | `backdrop-filter: blur(8px)` on sticky top navbar and sticky section eyebrow bar only (2 elements max) | Preserves readability of sticky navigation coordinates as content scrolls underneath; cards and modals remain solid matte surfaces. |
| **R-11** | `0px` (`rounded-none`) radius on buttons, nav cells, and grid bays; `2px` on code badges | Enforces the crisp technical-manual aesthetic of `getartcraft.com` and distinguishes interactive CTAs from data badges. |
| **R-12** | Elevation shadow used exclusively on floating command palette (`Cmd+K`) and modal dialogs | Separates modal overlay layers from the flat structural grid canvas; all page cards sit flat inside `1px` borders. |
| **R-13** | Zero decorative glow; `2px` focus ring on `:focus-visible` only | Guarantees keyboard navigation visibility without visual noise. |
| **R-14** | Flagship app showcase cards use asymmetric 2-column live workbench previews while catalog uses compact spec rows | Reflects hierarchy between flagship CNAPP pillars (CSPM, DSPM, CWPP, CIEM, ASPM) and specialized utilities. |
| **R-19** | `150ms` instant color-invert hover and `wgpu` pan/zoom canvas transitions | Provides immediate tactile confirmation of target selection and smooth graph traversal with zero endless loops. |
| **R-21** | Full Light (`#F2F1EE`), Dark (`#0B0B0C`), and System theme toggle in web navbar and `egui` top bar | Supports both daytime documentation reading (Warm Paper) and low-glare SecOps workbench analysis (Carbon Dark). |
| **R-22** | Deterministic offscreen-rendered app screenshots and interactive Wasm canvases | Shows the actual Rust `egui` applications operating on real security fixture corpora; zero stock or cartoon illustrations. |
