- display eligilbe headstash crops, different flavors (instances ), synced by headstash apis configured
- display claimed crops, maintain keys in custody kms for use (ledger/multisig/verifiable auth support)
- display miniapps to make use of (*bongs* rolling papers):
  - ibc withdraw
    - penumbra lp provide
    - osmsois lp provide
    - stargaze mint/infuse
    - ibc-hook (swap, stake,...)
    - minigames
- custom bdf font for app: <https://robey.lag.net/2010/01/23/tiny-monospace-font.html>
- custom design wrapper for egui app :

## Core Design Logic

egui's styling system is built around two main structures that control visual appearance and spatial layout:<cite></cite>

### 1. Style System (`Style` struct)

The `Style` struct in `crates/egui/src/style.rs` is the central configuration for egui's appearance [1](#0-0) . It contains:

- **`Visuals`**: Controls colors, strokes, fills, and visual properties [1](#0-0)
- **`Spacing`**: Controls distances, margins, padding, and sizes [2](#0-1)
- **`Widgets`**: Defines visual states (noninteractive, inactive, hovered, active, open) [3](#0-2)

### 2. Layout System (`Layout` struct)

The `Layout` struct in `crates/egui/src/layout.rs` controls spatial arrangement [4](#0-3) :

- **`main_dir`**: Main axis direction (left-to-right, top-to-bottom, etc.)
- **`main_wrap`**: Whether to wrap content
- **`main_align`** and **`cross_align`**: Alignment on both axes
- **`main_justify`** and **`cross_justify`**: Whether to justify content

## How to Modify the Skin

### Accessing and Modifying Styles

You can modify styles through the `Context`:<cite></cite>

1. **Change theme** (dark/light mode): Use `ctx.set_theme()` [5](#0-4)

2. **Modify current style**: Use `ctx.style_mut()` or `ctx.all_styles_mut()` [6](#0-5)

3. **Modify specific theme**: Use `ctx.style_mut_of(theme, |style| { ... })` [7](#0-6)

### Key Visual Properties

The `Visuals` struct defines the complete visual appearance [8](#0-7) :

- **Colors**: `override_text_color`, `hyperlink_color`, `warn_fg_color`, `error_fg_color`
- **Backgrounds**: `panel_fill`, `window_fill`, `extreme_bg_color`, `faint_bg_color`
- **Widget states**: Defined in `Widgets::dark()` and `Widgets::light()` [9](#0-8)
- **Shapes**: `window_corner_radius`, `handle_shape`, `button_frame`

### Widget Visual States

Each widget has 5 visual states defined in `WidgetVisuals` [3](#0-2) :

- **noninteractive**: Default appearance
- **inactive**: Not being interacted with but can be
- **hovered**: Mouse over the widget
- **active**: Being clicked/dragged
- **open**: For expandable widgets (menus, collapsing headers)

Each state defines: `weak_bg_fill`, `bg_fill`, `bg_stroke`, `fg_stroke`, `corner_radius`, `expansion` [10](#0-9)

## Design Philosophy

egui's styling follows these principles [11](#0-10) :

1. **Builder pattern**: Widgets use method chaining for configuration
2. **Immediate mode**: Styles are applied every frame, no retained state
3. **Single source of truth**: `Context` holds one `Style` that affects all widgets
4. **Theme-aware**: Separate dark and light mode styles that can be toggled

## Notes

The styling system is intentionally simpler than CSS but is being improved (see issue [#3284](https://github.com/emilk/egui/issues/3284)) [12](#0-11) . You can see a live example of custom styling in the demo app's style editor UI [13](#0-12) , which allows runtime modification of all style properties.

Wiki pages you might want to explore:

- [Overview (emilk/egui)](/wiki/emilk/egui#1)
- [Response and Interaction (emilk/egui)](/wiki/emilk/egui#2.4)

### Citations

**File:** crates/egui/src/style.rs (L919-1044)

```rust
/// Controls the visual style (colors etc) of egui.
///
/// You can change the visuals of a [`Ui`] with [`Ui::visuals_mut`]
/// and of everything with [`crate::Context::set_visuals_of`].
///
/// If you want to change fonts, use [`crate::Context::set_fonts`] instead.
#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct Visuals {
    /// If true, the visuals are overall dark with light text.
    /// If false, the visuals are overall light with dark text.
    ///
    /// NOTE: setting this does very little by itself,
    /// this is more to provide a convenient summary of the rest of the settings.
    pub dark_mode: bool,

    /// ADVANCED: Controls how we render text.
    pub text_alpha_from_coverage: AlphaFromCoverage,

    /// Override default text color for all text.
    ///
    /// This is great for setting the color of text for any widget.
    ///
    /// If `text_color` is `None` (default), then the text color will be the same as the
    /// foreground stroke color (`WidgetVisuals::fg_stroke`)
    /// and will depend on whether or not the widget is being interacted with.
    ///
    /// In the future we may instead modulate
    /// the `text_color` based on whether or not it is interacted with
    /// so that `visuals.text_color` is always used,
    /// but its alpha may be different based on whether or not
    /// it is disabled, non-interactive, hovered etc.
    pub override_text_color: Option<Color32>,

    /// How strong "weak" text is.
    ///
    /// Ignored if [`Self::weak_text_color`] is set.
    pub weak_text_alpha: f32,

    /// Color of "weak" text.
    ///
    /// If `None`, the color is [`Self::text_color`]
    /// multiplied by [`Self::weak_text_alpha`].
    pub weak_text_color: Option<Color32>,

    /// Visual styles of widgets
    pub widgets: Widgets,

    pub selection: Selection,

    /// The color used for [`crate::Hyperlink`],
    pub hyperlink_color: Color32,

    /// Something just barely different from the background color.
    /// Used for [`crate::Grid::striped`].
    pub faint_bg_color: Color32,

    /// Very dark or light color (for corresponding theme).
    /// Used as the background of text edits, scroll bars and others things
    /// that needs to look different from other interactive stuff.
    pub extreme_bg_color: Color32,

    /// The background color of [`crate::TextEdit`].
    ///
    /// Defaults to [`Self::extreme_bg_color`].
    pub text_edit_bg_color: Option<Color32>,

    /// Background color behind code-styled monospaced labels.
    pub code_bg_color: Color32,

    /// A good color for warning text (e.g. orange).
    pub warn_fg_color: Color32,

    /// A good color for error text (e.g. red).
    pub error_fg_color: Color32,

    pub window_corner_radius: CornerRadius,
    pub window_shadow: Shadow,
    pub window_fill: Color32,
    pub window_stroke: Stroke,

    /// Highlight the topmost window.
    pub window_highlight_topmost: bool,

    pub menu_corner_radius: CornerRadius,

    /// Panel background color
    pub panel_fill: Color32,

    pub popup_shadow: Shadow,

    pub resize_corner_size: f32,

    /// How the text cursor acts.
    pub text_cursor: TextCursorStyle,

    /// Allow child widgets to be just on the border and still have a stroke with some thickness
    pub clip_rect_margin: f32,

    /// Show a background behind buttons.
    pub button_frame: bool,

    /// Show a background behind collapsing headers.
    pub collapsing_header_frame: bool,

    /// Draw a vertical line left of indented region, in e.g. [`crate::CollapsingHeader`].
    pub indent_has_left_vline: bool,

    /// Whether or not Grids and Tables should be striped by default
    /// (have alternating rows differently colored).
    pub striped: bool,

    /// Show trailing color behind the circle of a [`Slider`]. Default is OFF.
    ///
    /// Enabling this will affect ALL sliders, and can be enabled/disabled per slider with [`Slider::trailing_fill`].
    pub slider_trailing_fill: bool,

    /// Shape of the handle for sliders and similar widgets.
    ///
    /// Changing this will affect ALL sliders, and can be enabled/disabled per slider with [`Slider::handle_shape`].
    pub handle_shape: HandleShape,

    /// Should the cursor change when the user hovers over an interactive/clickable item?
    ///
    /// This is consistent with a lot of browser-based applications (vscode, github
```

**File:** crates/egui/src/style.rs (L1524-1614)

```rust
impl Widgets {
    pub fn dark() -> Self {
        Self {
            noninteractive: WidgetVisuals {
                weak_bg_fill: Color32::from_gray(27),
                bg_fill: Color32::from_gray(27),
                bg_stroke: Stroke::new(1.0, Color32::from_gray(60)), // separators, indentation lines
                fg_stroke: Stroke::new(1.0, Color32::from_gray(140)), // normal text color
                corner_radius: CornerRadius::same(2),
                expansion: 0.0,
            },
            inactive: WidgetVisuals {
                weak_bg_fill: Color32::from_gray(60), // button background
                bg_fill: Color32::from_gray(60),      // checkbox background
                bg_stroke: Default::default(),
                fg_stroke: Stroke::new(1.0, Color32::from_gray(180)), // button text
                corner_radius: CornerRadius::same(2),
                expansion: 0.0,
            },
            hovered: WidgetVisuals {
                weak_bg_fill: Color32::from_gray(70),
                bg_fill: Color32::from_gray(70),
                bg_stroke: Stroke::new(1.0, Color32::from_gray(150)), // e.g. hover over window edge or button
                fg_stroke: Stroke::new(1.5, Color32::from_gray(240)),
                corner_radius: CornerRadius::same(3),
                expansion: 1.0,
            },
            active: WidgetVisuals {
                weak_bg_fill: Color32::from_gray(55),
                bg_fill: Color32::from_gray(55),
                bg_stroke: Stroke::new(1.0, Color32::WHITE),
                fg_stroke: Stroke::new(2.0, Color32::WHITE),
                corner_radius: CornerRadius::same(2),
                expansion: 1.0,
            },
            open: WidgetVisuals {
                weak_bg_fill: Color32::from_gray(45),
                bg_fill: Color32::from_gray(27),
                bg_stroke: Stroke::new(1.0, Color32::from_gray(60)),
                fg_stroke: Stroke::new(1.0, Color32::from_gray(210)),
                corner_radius: CornerRadius::same(2),
                expansion: 0.0,
            },
        }
    }

    pub fn light() -> Self {
        Self {
            noninteractive: WidgetVisuals {
                weak_bg_fill: Color32::from_gray(248),
                bg_fill: Color32::from_gray(248),
                bg_stroke: Stroke::new(1.0, Color32::from_gray(190)), // separators, indentation lines
                fg_stroke: Stroke::new(1.0, Color32::from_gray(80)),  // normal text color
                corner_radius: CornerRadius::same(2),
                expansion: 0.0,
            },
            inactive: WidgetVisuals {
                weak_bg_fill: Color32::from_gray(230), // button background
                bg_fill: Color32::from_gray(230),      // checkbox background
                bg_stroke: Default::default(),
                fg_stroke: Stroke::new(1.0, Color32::from_gray(60)), // button text
                corner_radius: CornerRadius::same(2),
                expansion: 0.0,
            },
            hovered: WidgetVisuals {
                weak_bg_fill: Color32::from_gray(220),
                bg_fill: Color32::from_gray(220),
                bg_stroke: Stroke::new(1.0, Color32::from_gray(105)), // e.g. hover over window edge or button
                fg_stroke: Stroke::new(1.5, Color32::BLACK),
                corner_radius: CornerRadius::same(3),
                expansion: 1.0,
            },
            active: WidgetVisuals {
                weak_bg_fill: Color32::from_gray(165),
                bg_fill: Color32::from_gray(165),
                bg_stroke: Stroke::new(1.0, Color32::BLACK),
                fg_stroke: Stroke::new(2.0, Color32::BLACK),
                corner_radius: CornerRadius::same(2),
                expansion: 1.0,
            },
            open: WidgetVisuals {
                weak_bg_fill: Color32::from_gray(220),
                bg_fill: Color32::from_gray(220),
                bg_stroke: Stroke::new(1.0, Color32::from_gray(160)),
                fg_stroke: Stroke::new(1.0, Color32::BLACK),
                corner_radius: CornerRadius::same(2),
                expansion: 0.0,
            },
        }
    }
}
```

**File:** crates/egui/src/style.rs (L1749-1772)

```rust
        ui.collapsing("📏 Spacing", |ui| spacing.ui(ui));
        ui.collapsing("☝ Interaction", |ui| interaction.ui(ui));
        ui.collapsing("🎨 Visuals", |ui| visuals.ui(ui));
        ui.collapsing("🔄 Scroll animation", |ui| scroll_animation.ui(ui));

        #[cfg(debug_assertions)]
        ui.collapsing("🐛 Debug", |ui| debug.ui(ui));

        ui.checkbox(compact_menu_style, "Compact menu style");

        ui.checkbox(explanation_tooltips, "Explanation tooltips")
            .on_hover_text(
                "Show explanatory text when hovering DragValue:s and other egui widgets",
            );

        ui.checkbox(url_in_tooltip, "Show url when hovering links");

        ui.checkbox(always_scroll_the_only_direction, "Always scroll the only enabled direction")
            .on_hover_text(
                "If scrolling is enabled for only one direction, allow horizontal scrolling without pressing shift",
            );

        ui.vertical_centered(|ui| reset_button(ui, self, "Reset style"));
    }
```

**File:** crates/egui/src/style.rs (L1789-1812)

```rust
impl Spacing {
    pub fn ui(&mut self, ui: &mut crate::Ui) {
        let Self {
            item_spacing,
            window_margin,
            menu_margin,
            button_padding,
            indent,
            interact_size,
            slider_width,
            slider_rail_height,
            combo_width,
            text_edit_width,
            icon_width,
            icon_width_inner,
            icon_spacing,
            default_area_size,
            tooltip_width,
            menu_width,
            menu_spacing,
            indent_ends_with_horizontal_line,
            combo_height,
            scroll,
        } = self;
```

**File:** crates/egui/src/layout.rs (L118-156)

```rust
// ----------------------------------------------------------------------------

/// The layout of a [`Ui`][`crate::Ui`], e.g. "vertical & centered".
///
/// ```
/// # egui::__run_test_ui(|ui| {
/// ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
///     ui.label("world!");
///     ui.label("Hello");
/// });
/// # });
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
// #[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Layout {
    /// Main axis direction
    pub main_dir: Direction,

    /// If true, wrap around when reading the end of the main direction.
    /// For instance, for `main_dir == Direction::LeftToRight` this will
    /// wrap to a new row when we reach the right side of the `max_rect`.
    pub main_wrap: bool,

    /// How to align things on the main axis.
    pub main_align: Align,

    /// Justify the main axis?
    pub main_justify: bool,

    /// How to align things on the cross axis.
    /// For vertical layouts: put things to left, center or right?
    /// For horizontal layouts: put things to top, center or bottom?
    pub cross_align: Align,

    /// Justify the cross axis?
    /// For vertical layouts justify mean all widgets get maximum width.
    /// For horizontal layouts justify mean all widgets get maximum height.
    pub cross_justify: bool,
}
```

**File:** crates/egui/src/context.rs (L2024-2026)

```rust
    pub fn set_theme(&self, theme_preference: impl Into<crate::ThemePreference>) {
        self.options_mut(|opt| opt.theme_preference = theme_preference.into());
    }
```

**File:** crates/egui/src/context.rs (L2062-2072)

```rust
    /// # let mut ctx = egui::Context::default();
    /// ctx.all_styles_mut(|style| {
    ///     style.spacing.item_spacing = egui::vec2(10.0, 20.0);
    /// });
    /// ```
    pub fn all_styles_mut(&self, mut mutate_style: impl FnMut(&mut Style)) {
        self.options_mut(|opt| {
            mutate_style(Arc::make_mut(&mut opt.dark_style));
            mutate_style(Arc::make_mut(&mut opt.light_style));
        });
    }
```

**File:** crates/egui/src/context.rs (L2091-2091)

```rust
    pub fn style_mut_of(&self, theme: Theme, mutate_style: impl FnOnce(&mut Style)) {
```

**File:** README.md (L256-259)

```markdown
### Can I customize the look of egui?
Yes! You can customize the colors, spacing, fonts and sizes of everything using `Context::set_style`.

This is not yet as powerful as say CSS, [but this is going to improve](https://github.com/emilk/egui/issues/3284).
```

**File:** README.md (L313-325)

```markdown
### Conventions and design choices

All coordinates are in screen space coordinates, with (0, 0) in the top left corner

All coordinates are in logical "points" which may consist of many physical pixels.

All colors have premultiplied alpha, unless otherwise stated.

egui uses the builder pattern for construction widgets. For instance: `ui.add(Label::new("Hello").text_color(RED));` I am not a big fan of the builder pattern (it is quite verbose both in implementation and in use) but until Rust has named, default arguments it is the best we can do. To alleviate some of the verbosity there are common-case helper functions, like `ui.label("Hello");`.

Instead of using matching `begin/end` style function calls (which can be error prone) egui prefers to use `FnOnce` closures passed to a wrapping function. Lambdas are a bit ugly though, so I'd like to find a nicer solution to this. More discussion of this at <https://github.com/emilk/egui/issues/1004#issuecomment-1001650754>.

egui uses a single `RwLock` for short-time locks on each access of `Context` data. This is to leave implementation simple and transactional and allow users to run their UI logic in parallel. Instead of creating mutex guards, egui uses closures passed to a wrapping function, e.g. `ctx.input(|i| i.key_down(Key::A))`. This is to make it less likely that a user would accidentally double-lock the `Context`, which would lead to a deadlock.
```

You are an expert Rust developer specializing in egui for immediate-mode GUIs, integrating blockchain APIs (Cosmos SDK, IBC, Keplr wallet integration), custom font rendering, and retro/analog-themed UI design. Your task is to generate clean, idiomatic Rust code that extends an existing egui application (using eframe for cross-platform support) with a custom "Headstash Crop Manager" window. This window displays and interacts with eligible/claimed "crops" (NFT-like yield assets or airdrop claims) synced via Headstash APIs, manages key custody with KMS support (Ledger/multisig/verifiable auth), and embeds miniapps for Cosmos ecosystem actions. Incorporate a custom BDF (Bitmap Distribution Format) font for monospace text in menus and labels, and apply a custom egui "skin" with analog/retro styling: use bitmapped icons for characters (e.g., farmers, avatars) and plants (crop visuals), scheme an analog dashboard feel (e.g., rounded gauges for progress, faux-analog dials for LP yields, striped backgrounds like old CRTs).

### Context and Assumptions

- The base application is a standard egui app with a main `update` loop. Assume it's a Cosmos wallet companion app with Keplr integration for signing (via `cosmos-sdk` and `ibc` crates; add deps if needed: `egui`, `eframe`, `reqwest` for APIs, `image` for bitmaps, `fontdue` or `egui_extras` for BDF font loading).
- Headstash API: Assume a configured client (`HeadstashClient`) that exposes async methods like:
  - `sync_eligible_crops(flavor: String) -> Vec<CropInfo>` (crops are instances/flavors like "Sativa", "Indica").
  - `claim_crop(crop_id: String, key: KmsKey) -> Result<ClaimedCrop, Error>`.
  - `get_claimed_crops() -> Vec<ClaimedCrop>`.
- `CropInfo`: Struct with `id: String`, `flavor: String`, `eligibility_score: f32`, `bitmap_url: String` (for plant icon), `status: CropStatus` (Eligible, Pending, Expired).
- `ClaimedCrop`: Similar, plus `yield_value: f64`, `custody_key: KmsKey` (enum: Ledger, Multisig, Verifiable).
- KMS Custody: Use a simple `KmsManager` for key ops (generate/store/sign; mock for demo, integrate real Ledger via `ledger-rs` if needed).
- Miniapps: Embed as collapsible panels or modal dialogs triggered by buttons. Assume async handlers:
  - `ibc_withdraw(amount: f64, dest_chain: String)`.
  - `penumbra_lp_provide(token_a: String, token_b: String, amount: f64)`.
  - `osmosis_lp_provide(...)` (similar).
  - `stargaze_mint_infuse(nft_data: String)`.
  - `ibc_hook_action(action: IbcHook, params: HashMap<String, String>)` (swap/stake).
  - `launch_minigame(game_id: String)` (e.g., simple egui-based puzzle).
- Custom BDF Font: Load the tiny monospace font from <https://robey.lag.net/2010/01/23/tiny-monospace-font.html> (assume downloaded as `tiny.bdf`; parse with `bdf` crate or manual bitmap loading into `egui::FontData`).
- Bitmaps: Load plant/character icons as `egui::TextureHandle` from URLs or embedded bytes (use `image::load`); display in grids with hover tooltips.
- Analog Scheme: Retro aesthetic – dark/greenish palette (e.g., #0a0a0a bg, #00ff41 accents like old terminals), analog gauges via `egui::plot` or custom painters (circular progress for yields), striped rows in tables, monospace BDF text for all menus/labels.
- Use egui's `Style` system: Override `Visuals` (dark_mode: true, custom colors/strokes from provided snippets), `Spacing` (compact: item_spacing: vec2(4.0, 2.0), indent: 8.0), `Widgets` states (hovered: expansion 1.5, fg_stroke thicker). Apply via `ctx.set_visuals()` in app init. For layout, use `Layout::top_down(Align::Center)` in panels for dashboard feel.
- Real-time sync: Poll Headstash API every 5s (use `tokio` for async); handle errors with toasts (egui notification crate if added).
- Window toggleable via main menu button.

### Requirements for the Generated Code

1. **Window Structure** (`HeadstashWindow` struct):
   - Title: "Headstash Crop Dashboard".
   - Size: ~1000x700, resizable, central.
   - Tabs or sections (use `egui::Tab` or `CollapsingHeader` for analog "panels"):
     - **Eligible Crops**: Grid/table of crops by flavor (columns: Flavor Icon (bitmap), ID, Score (analog gauge), Sync Status). Button: "Claim" → modal for KMS key selection (Ledger/Multisig dropdown + auth prompt).
     - **Claimed Crops**: Similar grid, plus Yield Gauge (circular analog dial via custom painter or `egui::Circle`), Custody Status (colored badge: 🔒 Ledger, 🔑 Multisig). Button: "Use Crop" → enqueue for miniapp.
     - **Miniapps (*Bongs & Rolling Papers*)**: Scrollable list of buttons/icons (retro paper textures as bg). Each opens a sub-window:
       - IBC Withdraw: Form with amount slider, dest chain dropdown; sign via Keplr.
       - LP Provide (Penumbra/Osmosis): Dual token selectors, ratio slider (analog needle), preview yield.
       - Stargaze Mint/Infuse: NFT upload/input, infuse progress bar (plant growth animation with bitmaps).
       - IBC-Hook: Dropdown (Swap/Stake), param fields; execute button.
       - Minigames: Embed simple egui game (e.g., match-3 crops with bitmap tiles).
     - **Settings**: API config (URL input), KMS toggle, Font reload button.

2. **Interactions & Visuals**:
   - Bitmaps: Load async into textures; display with `ui.image`; fallback to text icons (e.g., 🌱 for plants).
   - Menus: All text in BDF font (set via `ctx.set_fonts(FontDefinitions::from_bdf("tiny.bdf"))`); monospace for code-like feel, e.g., "Claim: crop_42 [Sativa]".
   - Analog Elements: Custom `AnalogGauge` widget (painter for arc/needle based on `progress: f32`); stripe tables with `faint_bg_color` alternating rows.
   - Hover/Click: Context menus on crops (right-click: Inspect bitmap, Share key). Flash green on sync success.
   - Auth: Verifiable prompts (e.g., "Sign with Ledger?"); mock multisig approval flow.
   - Error Handling: Red tooltips, retry buttons.

3. **egui Customization**:
   - Init in `main`: `ctx.set_visuals(Visuals::dark().with_override_text_color(Some(green)), ...)` using snippets (e.g., Widgets::dark() with custom grays/greens: bg_fill: #001100, fg_stroke: #00ff41).
   - Spacing: Compact retro (button_padding: vec2(2,1), interact_size: 16.0).
   - Layout: Mostly vertical with centered aligns; wrap grids for responsive.
   - Fonts: Load BDF as bytes, add to `FontDefinitions` with `FontData::Bytes`, set as default monospace.

4. **Integration**:
   - In main `update`: Button "Open Headstash Dashboard" toggles window.
   - Async: Use `Arc<Mutex<HeadstashClient>>` for thread-safety; spawn tokio tasks for sync.
   - Deps: Add `tokio`, `reqwest`, `serde`, `image`, `bdf-parser` (for font); assume Cosmos types from `cosmos-sdk-proto`.
   - Edge Cases: Empty lists (show retro "No crops harvested" bitmap), API offline (cached data), long bitmaps (scale to 32x32).

5. **Code Style**:
   - Rust 1.80+.
   - Modular: `headstash_window.rs` with `HeadstashWindow` impl `draw(ui: &mut Ui)`.
   - Comments: Key sections, e.g., "// Load BDF font and apply analog visuals".
   - Self-contained snippet + main.rs integration example.
   - Adapt: If Headstash API differs, note placeholders.

Generate the complete Rust code module (`headstash_window.rs`) with structs, custom widgets (e.g., `AnalogGauge`), font loader, and example `main.rs` integration. Include egui style setup from provided snippets (e.g., custom `Visuals` with dark_mode, weak_bg_fill: Color32::from_rgb(0,17,0)). Explain assumptions/extensions in comments.
