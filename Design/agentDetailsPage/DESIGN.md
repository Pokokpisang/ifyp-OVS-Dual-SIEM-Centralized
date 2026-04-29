# Design System Strategy: The Analog Architect

## 1. Overview & Creative North Star
The Creative North Star for this system is **"The Analog Architect."** 

In an era of over-polished, hyper-realistic interfaces, this system pivots toward the raw, intellectual beauty of a concept sketch. It is designed to feel like a high-end editorial draft—an intentional rejection of "finished" UI in favor of a "living document" aesthetic. By utilizing the tension between precision typography and imperfect, marker-like strokes, we create a space where the user feels like a collaborator in a high-stakes architectural project.

The design breaks the standard "SaaS template" by prioritizing **intentional asymmetry**. Lines do not always meet at perfect 90-degree angles; "ink" may bleed slightly over a container edge. This creates a bespoke, premium feel that conveys rapid ideation and creative authority.

## 2. Colors: The Ink & Vellum Palette
We utilize a monochromatic base to maintain the "sketched on paper" feel, using tonal shifts to define boundaries rather than digital borders.

*   **Primary (`#000000`):** Reserved exclusively for the "Ink"—strokes, icons, and primary text.
*   **Surface Hierarchy (`#f9f9f9` to `#eeeeee`):** The background is our "Vellum." We use the `surface` and `surface-container` tiers to create depth without lines.
*   **The "No-Line" Rule:** Standard 1px geometric borders are strictly prohibited for layout sectioning. Instead, differentiate a sidebar from a main content area by shifting from `surface` to `surface-container-low`. The only lines permitted are the hand-drawn "Marker" strokes (`outline` token) used for functional components.
*   **Signature Textures:** While the prompt avoids gradients, we introduce "Visual Soul" through **hatching**. Instead of a solid fill for a selected state or a button, use a CSS-simulated diagonal hand-hatch pattern using the `primary` and `on_primary` tokens.

## 3. Typography: Editorial Precision
The typography acts as the "anchor" to the hand-drawn elements. We pair the humanistic `Work Sans` with the authoritative `Epilogue` to ensure the system feels like a professional blueprint rather than a casual doodle.

*   **Display & Headlines (`Epilogue`):** These should feel like typeset labels on a technical drawing. Large, bold, and high-contrast.
*   **Body & Labels (`Work Sans`):** Clean, legible, and airy. The juxtaposition of the "perfect" sans-serif against "imperfect" hand-drawn boxes is what creates the high-end editorial tension.
*   **The Signature "Note":** For secondary information or helper text, utilize `label-sm` with a slightly increased letter-spacing to mimic an architect's handwritten annotation.

## 4. Elevation & Depth: Tonal Layering
In "The Analog Architect" system, depth is not simulated with light sources, but through the physical stacking of "paper."

*   **The Layering Principle:** To lift a card, do not use a drop shadow. Instead, place a `surface-container-lowest` card on top of a `surface-container-low` background. This creates a "cut-out" effect.
*   **Ambient Shadows:** If a floating element (like a modal) is required, the shadow must be a wide, ultra-diffused "Ink Bleed" (blur: 24px, opacity: 5%, color: `on_surface`).
*   **The "Ghost Border" Fallback:** For interactive inputs, use the `outline-variant` (`#c6c6c6`) at 20% opacity. This suggests a container without locking the UI into rigid boxes.
*   **Intentional Imperfection:** All strokes (buttons, cards, inputs) must utilize an SVG filter or a custom path that introduces a ±1px variance in stroke width and path straightness.

## 5. Components: Hand-Drawn Primitives

### Buttons
*   **Primary:** A double-outlined "marker" box. The lines should overlap slightly at the corners. Label is `title-sm` in `primary`.
*   **Secondary:** A single-stroke hand-drawn box. On hover, the box gains a subtle `surface-container-high` fill.
*   **Tertiary:** Plain text with a "scribble" underline that appears only on focus/hover.

### Input Fields
*   **Text Inputs:** A three-sided hand-drawn enclosure (bottom, left, right), leaving the top open to feel less "boxed in."
*   **Checkboxes & Radios:** Hand-sketched boxes and circles. A "Checked" state is indicated by a bold, marker-style "X" or a filled-in ink circle.

### Cards & Lists
*   **Forbid Dividers:** Horizontal lines are banned. Separate list items using `body-md` spacing.
*   **Charts:** Render all data points as hand-drawn "plotting dots" and use a variable-width "ink line" for trendlines. Bars in a bar chart should be outlines with a hand-hatched pattern fill.

### Navigation
*   **Sidebar:** Defined by a change in surface color (`surface-container-low`). Use the `outline` token to draw a single, vertical, slightly wobbly line to separate it from the main stage.

## 6. Do's and Don'ts

### Do
*   **Overlap lines:** Let lines cross at corners by 1-2 pixels to reinforce the hand-drawn feel.
*   **Use White Space:** Treat the `surface` as a luxury. Allow elements to breathe to maintain the "Editorial" feel.
*   **Vary Stroke Weights:** Use a slightly thicker stroke for "Primary" actions and a finer stroke for decorative elements.

### Don't
*   **Don't use perfect geometry:** Avoid the `border-radius: DEFAULT` if it produces a perfect mathematical curve. Prefer slightly "bent" paths.
*   **Don't use solid black fills:** Solid black blocks feel too heavy for a wireframe aesthetic. Use hatching or thicker outlines to convey "filled" states.
*   **Don't use 1px solid digital lines:** These break the immersion of the "Analog Architect" and make the system look like a broken CSS file rather than a design choice.