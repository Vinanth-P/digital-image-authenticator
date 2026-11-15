---
name: ImageGuard v2 Design System
description: x.ai / Linear / Palantir Foundry dark technical forensic workstation with crisp 1px structural hairlines, matte carbon surfaces, and anti-slop visual discipline.
DESIGN_VARIANCE: 4
MOTION_INTENSITY: 4
VISUAL_DENSITY: 8
colors:
  # Primary Matte Carbon & Alabaster Industrial Palette
  bg-primary: "#09090B"               # Pure matte obsidian carbon (no navy wash)
  bg-elevated: "#111113"              # Panel and command deck surface
  bg-card: "#141417"                  # Sub-panel and interactive surface
  bg-subtle: "#1C1C21"                # Hover and active selection state
  border-hairline: "#242429"          # 1px exposed structural grid lines
  border-bright: "#3F3F46"            # Focused / active border delineation
  text-primary: "#FAFAFA"             # Crisp alabaster ink
  text-secondary: "#A1A1AA"           # Neutral zinc body copy
  text-muted: "#71717A"               # Monospace labels and indices
  accent-primary: "#FAFAFA"           # Solid high-contrast primary button fill
  accent-text: "#09090B"              # Contrast bold dark text for primary buttons
  
  # Semantic Forensic Indicators
  accent-technical: "#10B981"         # Surgical Emerald for verified/authentic states
  verdict-authentic-bg: "#064E3B"     # Deep emerald surface
  accent-warning: "#F59E0B"           # Amber for splice manipulation warnings
  verdict-spliced-bg: "#451A03"       # Deep amber surface
  accent-danger: "#F43F5E"            # Crimson for synthetic AI vetoes
  verdict-synthetic-bg: "#4C0519"     # Deep crimson surface

typography:
  ui:
    fontFamily: "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
    fontSize: "0.875rem"
    lineHeight: 1.5
    letterSpacing: "-0.015em"
  data:
    fontFamily: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "0.8125rem"
    lineHeight: 1.4
    letterSpacing: "-0.02em"
    fontVariantNumeric: "tabular-nums"

rounded:
  sm: "4px"                           # Crisp architectural radii for buttons and badges
  md: "6px"                           # Panels and command cards
  lg: "8px"                           # Outer viewport containers

spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  2xl: "48px"
---

# ImageGuard v2 Visual System

## 1. Aesthetic Posture & Core Philosophy
ImageGuard v2 is an enterprise-grade digital media forensic workstation designed for security researchers, regulatory provenance auditors, and digital authenticity analysts.

Its aesthetic posture draws from `x.ai`, `Linear`, and `Palantir Foundry`:
- **Disciplined Matte Carbon & Alabaster**: Pure matte obsidian `#09090B` canvas with an architectural 48px hairline grid, elevated `#111113` command decks, and crisp `#FAFAFA` alabaster typography.
- **Structural Hairlines**: Crisp 1px `#242429` structural borders defining an exposed engineering grid.
- **Asymmetric Command Deck**: Left-aligned high-impact typography paired with interactive system architecture blueprints and live telemetry readouts.
- **Strict Anti-Slop Discipline**:
  1. Zero purple/indigo/navy radial washes or gradients (`#6366f1`, `#8b5cf6`, `linear-gradient` text or buttons).
  2. Primary buttons are solid `#FAFAFA` with `#09090B` bold text and `4px` border radius (zero glowing purple pills).
  3. No emojis in UI chrome (replaced with crisp inline 16px/20px stroke SVGs).
  4. Tabular numerals (`tabular-nums`) and `JetBrains Mono` strictly enforced across all scores, SHA-256 hashes, Merkle roots, and latencies.

---

## 2. Palette & Semantic Color Roles
- **Canvas Base (`--bg-primary`):** `#09090B` (True matte dark carbon).
- **Elevated Decks (`--bg-elevated`):** `#111113` with 1px border `#242429`.
- **Card / Sub-Panel (`--bg-card`):** `#141417` for interactive cards and dropzones.
- **Interactive Hover (`--bg-subtle`):** `#1C1C21`.
- **Structural Hairline (`--border-hairline`):** `#242429`.
- **Focused Border (`--border-bright`):** `#3F3F46`.
- **Primary Ink (`--text-primary`):** `#FAFAFA`.
- **Secondary Zinc (`--text-secondary`):** `#A1A1AA`.
- **Monospace Labels (`--text-muted`):** `#71717A`.
- **Forensic Verdict Spectrum:**
  - **Authentic Media:** `#10B981` (Emerald), surface `#064E3B`, border `#047857`.
  - **AI-Generated / Synthetic Media:** `#F43F5E` (Crimson), surface `#4C0519`, border `#BE123C`.
  - **Manipulated / Spliced Forgery:** `#F59E0B` (Amber), surface `#451A03`, border `#B45309`.

---

## 3. Typography
- **Primary Interface Font:** `'Inter'`, sans-serif (weights 400, 500, 600, 700). Tracking `-0.015em` to `-0.035em`.
- **Telemetry & Data Font:** `'JetBrains Mono'`, monospace with `font-variant-numeric: tabular-nums` strictly applied to:
  - Fused Authenticity Scores (0.0% – 100.0%)
  - Gate 1 Tamper Integrity ($G_1$) and Gate 2 Origin Integrity ($G_2$)
  - ELA, SRM Noise, 2D FFT Slope ($\alpha$), and CIFAKE/ViT $P(\text{AI})$ probabilities
  - SHA-256 Binary Digests & Perceptual dHash (16 hex)
  - Merkle Tree Leaf Hashes & Ledger Roots (64 hex)
  - Millisecond Processing Latencies ($P50$, $P99$)
