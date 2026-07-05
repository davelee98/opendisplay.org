# BLE Connection Bug Analysis — opendisplay.org

> Root-cause analysis of Web Bluetooth (BLE) connection problems, with special
> focus on mobile iOS (Bluefy browser) and the "dialog won't launch unless in
> developer mode" issue. Findings are recorded here so any session can pick up
> the fix work.

## Context
Two reported problems with the BLE flows on opendisplay.org:
1. Connecting to devices is buggy on mobile iOS, where users must use the
   **Bluefy** browser (iOS Safari has no Web Bluetooth support).
2. The **BLE connection dialog does not launch at all unless the browser is in
   "developer mode."**

All BLE flows funnel through one file: `httpdocs/js/ble-common.js` (class
`OpenDisplayBLE`). The only `navigator.bluetooth.requestDevice()` call in the
repo is `ble-common.js:389`. Four pages consume it: `firmware/display`,
`firmware/battery`, `firmware/toolbox`, `designer`.

---

## Root causes

### A. "Dialog won't launch unless in developer mode" (the reported blocker)
`requestDevice()` requires a **live user activation** (must be reached
synchronously inside a click handler). There is **no "developer mode" in the
codebase** — it is an external browser flag (Chrome
`chrome://flags/#enable-experimental-web-platform-features`, or Bluefy's
developer setting) that *relaxes* the user-gesture requirement. So the code
paths that call `requestDevice()` without a gesture only work when that flag is
on.

Two non-gesture call paths:
1. `httpdocs/firmware/display/index.html:2529-2531` — auto-connect on page load
   via `setTimeout(() => { preConnect(); }, 500)` when `?connect=true` /
   `?auto=true` + filter param is present (reached from the toolbox → display
   redirect).
2. `httpdocs/firmware/toolbox/index.html:3582` — post-reboot reconnect loop in
   `waitForDeviceReboot`, `await connectToBleDevice()` after multi-second
   `await delay(...)` chains (activation long expired).

Compounding: `connect()`'s catch (`ble-common.js:396-404`) only handles
`NotFoundError`/`AbortError`; the `SecurityError` from a lost gesture produces
no message — it just appears to do nothing.

All **button-wired** paths (`display:2267`, `battery:302`, `toolbox:1109`,
`designer:3986`) reach `requestDevice()` synchronously within the gesture and
are fine.

### B. iOS / Bluefy connection bugs
1. **Missing feature detection on 3 of 4 pages.** Only
   `firmware/display/index.html:2220` checks `navigator.bluetooth` and shows the
   "use Bluefy" alert. `designer:3986`, `battery:302`/`:584`,
   `toolbox:1109`/`:2652` throw a raw `TypeError` on unsupported browsers.
2. **`writeValueWithoutResponse` with no fallback.** Every command goes through
   `sendCommand` → `writeValueWithoutResponse` (`ble-common.js:706`); no
   `writeValueWithResponse` anywhere. WebKit/Bluefy is flaky here; the retry
   loop (line 709) only catches `NetworkError`, so other failures throw out.
   Likely cause of "pairs then fails on first command" on iOS.
3. **16-bit UUID shorthand `0x2446`** passed to `optionalServices`,
   `getPrimaryService`, `getCharacteristic` (`ble-common.js:14-15, 480, 537`).
   Bluefy/iOS often need the canonical 128-bit UUID string.
4. Hardcoded timings not tuned for iOS (`300ms` stabilize at `:554`).
5. **Quadratic config-write delay**: `ble-common.js:2702` uses
   `await this.delay(i * 150)` (cumulative) → ~`150·N(N-1)/2` ms for N chunks.
6. **Disconnect-listener leak**: added as `() => this.handleDisconnect()`
   (`:393`) but removed via `this.handleDisconnect` (`:608`) — never removed.

Auto-reconnect (`handleDisconnect` → cached `device.gatt.connect()`) correctly
avoids re-prompting; it is iOS-safe.

---

## Priority

| # | Fix | File | Severity |
|---|-----|------|----------|
| 1 | Non-gesture `requestDevice()` (dialog never opens off dev-flag) | `display:2529`, `toolbox:3582` | **Critical** |
| 2 | No feature detection → raw TypeError instead of Bluefy prompt | designer, battery, toolbox | High |
| 3 | `writeValueWithoutResponse` w/ no `writeValueWithResponse` fallback | `ble-common.js:706` | High (iOS) |
| 4 | 16-bit vs canonical 128-bit UUID | `ble-common.js:14-15,480,537` | Medium (iOS) |
| 5 | `SecurityError` unhandled in connect catch | `ble-common.js:396` | Medium |
| 6 | Quadratic `i*150` config-write delay | `ble-common.js:2702` | Low |
| 7 | Disconnect-listener never removed | `ble-common.js:393/608` | Low |

---

## Recommended fix approach (not yet implemented)

- **#1** Replace the auto-connect UX: instead of firing `requestDevice()` from a
  `setTimeout`, render a one-tap "Connect" button (pre-filled with the filter
  from the URL) so the chooser is opened inside a real gesture. For the
  post-reboot reconnect (`toolbox:3582`), reconnect via the **cached device**
  (`device.gatt.connect()`), not a fresh `requestDevice()`.
- **#2** Add a shared feature-detection helper (or reuse the display page's
  check at `display:2220`) at the top of every `connect`/`preConnect` handler,
  showing the Bluefy guidance.
- **#3** Add a `writeValueWithResponse` fallback in `sendCommand`
  (`ble-common.js:681-718`) when `writeValueWithoutResponse` is unavailable or
  throws a non-retryable error.
- **#4** Define `0x2446` as a canonical 128-bit UUID string and use it in
  `optionalServices` / `getPrimaryService` / `getCharacteristic`.
- **#5** Handle `SecurityError` in the `connect()` catch with a clear
  "tap Connect to open the device chooser" message.
- **#6/#7** Fix the cumulative delay (use a flat per-chunk delay) and the
  listener removal (store the bound handler reference).

## Verification
- Desktop Chrome: confirm the Connect button opens the chooser with the flag
  OFF; confirm `?connect=true` links now show a tap-to-connect prompt rather
  than silently failing.
- iOS Bluefy: confirm feature detection passes, chooser opens, a config
  read/write round-trips (exercises `writeValueWithoutResponse` path + UUID).
- Confirm reconnect after a device reboot succeeds without a second chooser.

## Files to modify
- `httpdocs/js/ble-common.js` (core: #3, #4, #5, #6, #7)
- `httpdocs/firmware/display/index.html` (#1 auto-connect)
- `httpdocs/firmware/toolbox/index.html` (#1 reboot reconnect)
- `httpdocs/designer/index.html`, `httpdocs/firmware/battery/index.html` (#2)
