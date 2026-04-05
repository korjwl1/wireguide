---
name: macos-native-ui
description: Apply macOS Human Interface Guidelines + WCAG 2.2 AA accessibility mandates to desktop app interfaces (especially Wails/Electron webviews that should feel native). Use when refining existing UI to match macOS look & feel, when the user asks for "native Mac feel", when fixing contrast/spacing/typography issues, or when building new views that must integrate with the macOS desktop.
---

This skill encodes the concrete numeric values and mandatory rules from:

- **Apple Human Interface Guidelines** (macOS Sonoma / Sequoia, 2024–2025)
- **WCAG 2.2 Level AA** accessibility requirements
- **macOS AppKit system semantic colors** (dynamic light/dark)

It exists because the other frontend design skill is about "bold creative direction", which is useful for marketing sites but not for apps that must feel like they belong on a Mac desktop. macOS users have calibrated expectations — font size, row height, shadow depth, corner radius — and breaking those expectations makes even a beautiful app feel foreign.

---

## 0. When to apply this skill

Apply it whenever you touch `.svelte` / `.css` / `.tsx` files in a Wails v3, Tauri, or Electron app that targets macOS. Apply it proactively when the user says things like "looks off", "not quite right", "needs refinement", "match macOS". Do NOT apply it to marketing pages, landing sites, or anything that should feel expressive/bold — those want the `frontend-design` skill.

---

## 1. HARD RULES — mandatory, no exceptions

These are WCAG 2.2 AA requirements. Violating them is a bug.

1. **Text contrast ≥ 4.5:1** against its background. Large text (≥18pt or ≥14pt bold) may drop to 3:1. Inactive/disabled text is exempt. Verify with a contrast checker — don't eyeball it.
2. **UI component contrast ≥ 3:1** — borders, input outlines, focus rings, icons that convey meaning. A 1px border on a form field at `#e5e5e5` over `#ffffff` FAILS (1.3:1) — use `#c7c7c7` (3.1:1) minimum.
3. **Focus indicators must be visible** — never `outline: none` without providing an alternative. Mac users use keyboard navigation heavily.
4. **Interactive targets ≥ 24×24 CSS pixels** (WCAG 2.5.8). Apple HIG recommends 44×44 for touch but 22×22 for mouse/trackpad — use 24 as the floor for keyboard + trackpad.
5. **Respect `prefers-reduced-motion`**: wrap every transition/animation in `@media (prefers-reduced-motion: no-preference)` or shorten/remove when it's set.
6. **Respect `prefers-color-scheme`** (we already do this via CSS variables).
7. **Every interactive element has an accessible name** — `aria-label`, visible text, or `title`.
8. **No color-only meaning** — pair every colored indicator with an icon, text, or shape.

---

## 2. Color tokens (macOS-aligned)

Use these as the source of truth for CSS variables. Names match Apple's semantic color vocabulary where applicable so future contributors recognize them.

### System accent colors (light mode → dark mode)

| Token | Light | Dark | Use for |
|---|---|---|---|
| `--accent-blue` | `#007AFF` | `#0A84FF` | Primary buttons, links, selected rows |
| `--accent-green` | `#34C759` | `#30D158` | Success, connected state |
| `--accent-red` | `#FF3B30` | `#FF453A` | Destructive, errors, disconnected-danger |
| `--accent-orange` | `#FF9500` | `#FF9F0A` | Warnings, in-progress |
| `--accent-yellow` | `#FFCC00` | `#FFD60A` | Connecting, attention |
| `--accent-purple` | `#AF52DE` | `#BF5AF2` | Secondary actions |
| `--accent-teal` | `#30B0C7` | `#40C8E0` | Info, neutral highlight |
| `--accent-indigo` | `#5856D6` | `#5E5CE6` | Brand accent (alt) |
| `--accent-pink` | `#FF2D55` | `#FF375F` | (reserved) |

### Surface / background

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg-primary` | `#FFFFFF` | `#1E1E1E` | Main content background |
| `--bg-secondary` | `#F5F5F7` | `#2A2A2E` | Sidebar, secondary panels |
| `--bg-tertiary` | `#EEEEF0` | `#323236` | Raised card, popover |
| `--bg-input` | `#FFFFFF` | `#1E1E1E` | Text field background |
| `--bg-hover` | `rgba(0,0,0,0.06)` | `rgba(255,255,255,0.08)` | Hover overlay |
| `--bg-selected` | `rgba(0,122,255,0.10)` | `rgba(10,132,255,0.20)` | Selected row (tinted with accent-blue) |
| `--bg-active` | `rgba(0,0,0,0.08)` | `rgba(255,255,255,0.10)` | Pressed state |

### Label / text hierarchy (matches AppKit `labelColor` family)

| Token | Light | Dark | Use |
|---|---|---|---|
| `--text-primary` | `#000000E6` (90%) | `#FFFFFFE6` (90%) | Body text, titles |
| `--text-secondary` | `#0000008C` (55%) | `#FFFFFF8C` (55%) | Metadata, captions |
| `--text-tertiary` | `#00000066` (40%) | `#FFFFFF66` (40%) | Placeholder, disabled |
| `--text-quaternary` | `#00000040` (25%) | `#FFFFFF40` (25%) | Decorative only |
| `--text-inverse` | `#FFFFFF` | `#FFFFFF` | On colored buttons |
| `--text-link` | `var(--accent-blue)` | `var(--accent-blue)` | Hyperlinks |

Note the use of **percentage alphas over pure black/white** rather than flat grays. This is how macOS actually renders `labelColor` — the label adapts to any background through the alpha, matching Apple's dynamic behavior.

### Separator / border

| Token | Light | Dark | Use |
|---|---|---|---|
| `--separator` | `rgba(60,60,67,0.29)` | `rgba(84,84,88,0.65)` | Horizontal divider lines |
| `--border-strong` | `rgba(60,60,67,0.36)` | `rgba(84,84,88,0.72)` | Form field borders |
| `--border-subtle` | `rgba(60,60,67,0.18)` | `rgba(84,84,88,0.40)` | Card outlines |

These alphas are the EXACT values AppKit uses for `separatorColor` and `opaqueSeparatorColor`.

### Semantic overlays

| Token | Light | Dark |
|---|---|---|
| `--overlay-backdrop` | `rgba(0,0,0,0.35)` | `rgba(0,0,0,0.55)` |
| `--overlay-drop` | `rgba(0,122,255,0.18)` | `rgba(10,132,255,0.25)` |
| `--shadow-xs` | `0 0 0 0.5px rgba(0,0,0,0.08), 0 1px 1px rgba(0,0,0,0.04)` | `0 0 0 0.5px rgba(255,255,255,0.08), 0 1px 1px rgba(0,0,0,0.40)` |
| `--shadow-sm` | `0 1px 2px rgba(0,0,0,0.06), 0 2px 6px rgba(0,0,0,0.08)` | `0 1px 2px rgba(0,0,0,0.30), 0 2px 6px rgba(0,0,0,0.40)` |
| `--shadow-md` | `0 4px 12px rgba(0,0,0,0.12), 0 16px 48px rgba(0,0,0,0.08)` | `0 4px 12px rgba(0,0,0,0.40), 0 16px 48px rgba(0,0,0,0.30)` |
| `--shadow-lg` | `0 20px 60px rgba(0,0,0,0.15)` | `0 20px 60px rgba(0,0,0,0.55)` |

---

## 3. Typography

Use the system font stack so macOS renders with SF Pro automatically:

```css
--font-sans: -apple-system, BlinkMacSystemFont, "SF Pro Text", "SF Pro Display",
             "Helvetica Neue", Helvetica, Arial, sans-serif;
--font-mono: ui-monospace, "SF Mono", Menlo, Monaco, "Cascadia Mono",
             "Roboto Mono", Consolas, monospace;
```

Never use Inter, Roboto, or custom web fonts on macOS app chrome — SF Pro is already cached by the OS and tracks OS-wide font preferences (font smoothing, text scaling for accessibility).

### macOS AppKit text style scale

| Role | Size | Line height | Weight | Tracking | Notes |
|---|---|---|---|---|---|
| Large Title | 26px | 32px | 700 | -0.02em | Window titles, empty-state headers |
| Title 1 | 22px | 28px | 700 | -0.015em | Section headers |
| Title 2 | 17px | 22px | 700 | -0.01em | Subsection headers |
| Title 3 | 15px | 20px | 600 | -0.005em | Card headers |
| Headline | 13px | 18px | 600 | 0 | Emphasised body, tunnel name |
| **Body** | **13px** | **18px** | **400** | **0** | **Default body text on macOS** |
| Callout | 12px | 16px | 400 | 0 | Secondary body |
| Subheadline | 11px | 14px | 400 | 0.02em | Sidebar items, small labels |
| Footnote | 10px | 13px | 400 | 0.04em | Timestamps, metadata |
| Caption | 10px | 13px | 500 | 0.06em uppercase | Section labels above groups |

**Key difference from web apps**: macOS body text is **13px, not 16px**. Web defaults of 16px make macOS UIs look oversized and clunky. Use 13px body.

Font smoothing:
```css
-webkit-font-smoothing: antialiased;
-moz-osx-font-smoothing: grayscale;
```

---

## 4. Spacing scale (8pt grid + 4pt substeps)

Use **8px as the base unit** with 4px half-steps for fine tuning. Avoid arbitrary values like 7px or 13px.

```css
--space-1: 4px;    /* tightest — between icon and adjacent text */
--space-2: 8px;    /* compact — between related controls */
--space-3: 12px;   /* default inline gap */
--space-4: 16px;   /* section internal padding */
--space-5: 20px;   /* window/panel content padding */
--space-6: 24px;   /* between distinct sections */
--space-8: 32px;   /* major section breaks */
--space-10: 40px;  /* empty-state padding */
--space-12: 48px;  /* hero/landing gaps only */
```

### Row heights (follow AppKit conventions)

- **List row (compact)**: 24px
- **List row (standard)**: 28px — this is AppKit's default `NSTableView` row height
- **List row (comfortable)**: 36px — for touch-friendly or rich rows
- **Menu item**: 22px
- **Toolbar button**: 28px, 32px large
- **Form field**: 22px small, 28px regular, 32px large

### Content width

- **Sidebar**: 220–260px (250px is the AppKit default)
- **Modal/dialog**: 420px preferred, 560px max for content-heavy
- **Minimum window width**: 640px

---

## 5. Radius

macOS uses smaller radii than modern web design trends. Don't over-round.

```css
--radius-xs: 4px;   /* small buttons, tags, chips */
--radius-sm: 6px;   /* default buttons, inputs, small cards */
--radius-md: 8px;   /* cards, popovers */
--radius-lg: 10px;  /* windows, large panels (matches AppKit window radius) */
--radius-xl: 14px;  /* only for hero cards */
```

**Don't use `border-radius: 9999px` (fully round pills)** unless it's specifically a badge or avatar. macOS buttons are subtly rounded rectangles.

---

## 6. Motion

macOS animations are **fast and purposeful**. No bouncy springs, no slow fades.

```css
--ease-out: cubic-bezier(0.2, 0, 0.1, 1);       /* most UI transitions */
--ease-in-out: cubic-bezier(0.4, 0, 0.2, 1);   /* symmetric transitions */
--ease-sheet: cubic-bezier(0.32, 0.72, 0, 1);  /* sheets, popovers (Apple's standard) */

--dur-fast: 120ms;    /* hover, active state */
--dur-base: 220ms;    /* most transitions */
--dur-slow: 320ms;    /* sheet present / dismiss */
--dur-hero: 450ms;    /* one-off window entry */
```

Always wrap in reduced-motion check:

```css
@media (prefers-reduced-motion: no-preference) {
  .card { transition: transform var(--dur-base) var(--ease-out); }
}
```

**Do not** animate layout-triggering properties (width, height, top, left). Animate `transform` and `opacity` only.

---

## 7. Component patterns specific to macOS feel

### Buttons

Three tiers — matching macOS `NSButton` bezel styles.

```css
/* Primary (filled, accent-coloured) */
.btn-primary {
  background: var(--accent-blue);
  color: var(--text-inverse);
  border: 0;
  height: 22px; padding: 0 12px;
  border-radius: var(--radius-sm);
  font: 600 13px var(--font-sans);
}
.btn-primary:hover { filter: brightness(1.08); }
.btn-primary:active { filter: brightness(0.94); }

/* Secondary (outlined / gray) */
.btn-secondary {
  background: var(--bg-secondary);
  color: var(--text-primary);
  border: 0.5px solid var(--border-strong);
  /* ... same sizing ... */
}

/* Destructive */
.btn-destructive { background: var(--accent-red); color: var(--text-inverse); }

/* Tertiary / ghost (text only) */
.btn-ghost {
  background: transparent;
  color: var(--accent-blue);
  border: 0;
}
```

Button heights **22px for compact, 28px for regular, 32px for large**. NOT 40 or 48px — that's web / mobile.

### List rows

```css
.row {
  display: flex; align-items: center;
  height: 28px;                       /* AppKit default */
  padding: 0 var(--space-3);
  gap: var(--space-2);
  font-size: 13px;
  color: var(--text-primary);
  border-radius: var(--radius-xs);   /* inset look */
  margin: 0 var(--space-2);
}
.row:hover { background: var(--bg-hover); }
.row[aria-selected="true"] {
  background: var(--bg-selected);
  color: var(--text-primary);
}
```

Rows should NOT have separator lines between them by default — Mac users rely on hover + selection highlights. Only add separators for visually crowded content.

### Sidebar

macOS sidebars use a slightly translucent look. In a webview we can't use real `NSVisualEffectView` vibrancy, but we can approximate:

```css
.sidebar {
  width: 220px;
  background: var(--bg-secondary);
  border-right: 0.5px solid var(--separator);
  padding: var(--space-2) 0;
}
```

### Toolbar

```css
.toolbar {
  height: 52px;        /* standard macOS toolbar height */
  padding: 0 var(--space-4);
  border-bottom: 0.5px solid var(--separator);
  display: flex; align-items: center; gap: var(--space-2);
}
```

Prefer **half-pixel (0.5px) borders** for the hairline look characteristic of macOS. In webviews on Retina displays, 0.5px renders crisply.

### Focus rings

```css
:focus-visible {
  outline: 2px solid var(--accent-blue);
  outline-offset: 2px;
  border-radius: var(--radius-sm);
}
```

**Never** `outline: none` without a replacement. Use `:focus-visible` (not `:focus`) so mouse clicks don't trigger rings.

---

## 8. Workflow when applying this skill

1. **Read** the target file(s) you're refining
2. **Audit** against sections 1 (hard rules), 2 (colors), 3 (typography), 4 (spacing)
3. **Plan** which specific selectors/components need changes — write them down before editing
4. **Edit** in small passes: one pass for color tokens, one for typography, one for spacing, one for components
5. **Verify**:
   - `grep -rn "#[0-9a-fA-F]{3,6}"` — any hardcoded hex left outside the palette file?
   - `grep -rn "font-size: [0-9]"` — any non-token sizes?
   - `grep -rn "outline: none"` — any focus kill?
   - Contrast spot-check on changed colors
   - Build and run if possible

---

## 9. Anti-patterns (never do these on a Mac app)

- **16px body text** — too big for desktop. Use 13px.
- **Rounded-full pills for everything** — looks like a mobile app.
- **Gradient purple hero backgrounds** — instantly screams "AI-generated web SaaS".
- **Inter / Roboto / generic Google Fonts** — use system font on macOS.
- **24px+ shadows with huge blurs** — macOS shadows are subtle, 0–20px range.
- **"Animated on scroll"** — macOS apps don't do parallax.
- **Colour-only error indication** — pair with an icon or label.
- **Focus rings removed without replacement** — a11y violation + Mac users use keyboard.
- **Tailwind default gray palette** (`gray-100`, `gray-900` etc.) — they're flat, use label-family alphas.
- **48px button heights** — too tall. 22/28/32.
- **`transition: all`** — animates layout-triggering properties too. List specific properties.

---

## 10. Sources

- [Apple Human Interface Guidelines](https://developer.apple.com/design/human-interface-guidelines) — master reference (JS-required, use Xcode or Figma design resources for exact tokens)
- [WCAG 2.2 Level AA](https://www.w3.org/TR/WCAG22/) — contrast, focus, interaction
- [Apple HIG Color (Figma)](https://www.figma.com/community/file/1118467272498298301/apple-hig-colors-ios) — official token values
- [WebAIM Contrast Checker](https://webaim.org/resources/contrastchecker/) — verify contrast ratios
- AppKit semantic colors reference: https://developer.apple.com/documentation/appkit/nscolor/ui_element_colors
