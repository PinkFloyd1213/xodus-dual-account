# Two accounts: `store` (licenses) and `play` (in-game identity)

> **Status: backend and Nexus fork implemented, tested and in use**
> (`dual-account` branches of both forks). Verified in game on 22.10.2026:
> `MsaTokenRequest` uses `play`, cloud saves sync for the personal account,
> achievements and time played follow it. User guide: `docs/DUAL_ACCOUNT.md`
> in the Nexus fork.
>
> Goal: reproduce Windows. The account that has Game Pass (`store`) is used
> only for licenses, in the background, like the Microsoft Store. Everything
> the user sees (in-game identity, gamertag, achievements, playtime, cloud
> saves), both in game and in the launcher, is the personal account (`play`),
> like the Xbox app.
>
> Maintained as forks ([xodus-dual-account](https://github.com/PinkFloyd1213/xodus-dual-account),
> [xodus-nexus-dual-account](https://github.com/PinkFloyd1213/xodus-nexus-dual-account)),
> but written to stay mergeable: additive changes, no refactoring, identical
> behavior as long as no `play` account is configured.

## Baseline

| Item | Value |
|---|---|
| Nexus read | `domsvoboda/xodus-nexus` @ `59fb0798f034` (21.10.2026) |
| Backend lock | version `0.2.10`, commit `53ea781dcd07`, patchId `linux-run-v38`, compatibility `linux-run-v22`, rust `1.99.0` |
| `Cargo.lock` | sha256 matches the lock (`2259b343…`) |
| `nexus-base` branch | pinned commit + the 38 patches from the lock, applied in order (`git apply --check` then `git apply`, like `backend.ts` and `scripts/build-backend.mjs`), one commit per patch, sha256 verified for each |
| Build | `cargo build --locked --release --no-default-features -p xodus-cli -p xodus-service` with rustc 1.99.0: OK |
| Capabilities | `--help` exposes everything `parseBackendHelp`/`validate()` and `build-backend.mjs` expect (account, profile, game-activity, achievements, library, login, logout, download, streaming, run, resolve-package, keyring-*, `--external-webview-stdio`, `--progress-json`, `--control-stdin`, `--download-limit-kib`, `--selected-content-id`, `run --materialize-chain`). No native webview library linked. |

Note: the lock does **not** contain a separate `LINUX_RUN_PATCH`.
`LINUX_RUN_PATCH` is simply `lock.compatibility` (`linux-run-v22`); the
"linux-run patch" is `xodus-linux-run.patch`, the first one in the list.

## Current storage (patched state)

`TokenManager` (`crates/xodus/src/tokens/manager.rs`) writes to the Secret
Service keyring, collection/service `Xodus Service`, under these keys:

| Key | Content | Role |
|---|---|---|
| `user-session` | account + full set of STS (format written by `login` from `xodus-keyring-credentials`) | user |
| `user-tokens`, `user-DA` | old split format, still read if `user-session` is absent | user |
| `device-tokens` | device STS | device |
| `dev_license` | device identity + license | device |
| `nexus-subscription-v2` | 10-min subscription cache, tied to `username` (`commands/subscription.rs`) | `store` |

The ephemeral XSTS cache (`get_cached_xsts`/`cache_xsts`, in memory) has
**no callers** today.

## What the game sends to the service

The Nexus Wine runtime (`assets/xgameruntime-*.patch`) sends only four
messages to `xodus-service` (`crates/xodus/proto/xodus/common.proto`):
`PING`, `MSA_TOKEN_REQUEST`, `STORE_LICENSE_TOKEN_REQUEST`,
`STORE_PACKAGE_UPDATES_REQUEST`. The protobuf path is `unimplemented!`.

Everything else is done **in the runtime** from the token returned by
`MSA_TOKEN_REQUEST`: XUser, game-service XSTS, cloud saves
(`titlestorage.xboxlive.com/connectedstorage/users/xuid(...)`, via
`xuser_device_authorization`), gamerpic, etc. Routing `MSA_TOKEN_REQUEST` to
`play` is therefore enough to route the **entire** in-game identity through `play`.

The runtime's XStore APIs (`xstore_entitled.h`, `xstore_receipts.h`,
package license) go **only** through `STORE_LICENSE_TOKEN_REQUEST`. They
read the XUID from the XUser but do not send it to the service. The patch says
so explicitly: *"The existing receipt transport uses the service's
authenticated Store account, not Xbox profile metadata."*

## Map

Paths relative to `crates/`. Line numbers as of `nexus-base`.

### Model (`xodus`)

| Location | Function | Proposed role | Rationale |
|---|---|---|---|
| `xodus/src/tokens/manager.rs:10-16` | keyring keys | `store` = current keys; `play` = `play/user-session` (+ `play/user-tokens`, `play/user-DA` for symmetry) | no migration; the existing data becomes `store` |
| `manager.rs:65` | `remove_persistent` | `store` (+ `device-tokens`, as today) | current `logout` behavior |
| `manager.rs:76-109` | device license / device STS | device, shared | a single device, as on Windows |
| `manager.rs:113` `:120` `:132` | `get_user_token_for`, `save_user_token`, `get_user_sts_token` | parameterized by role | core of the change |
| `manager.rs:139` `:150` `:158` `:168` | `get_user`, `save_user`, `user_session`, `save_user_session` | parameterized by role | same |
| `manager.rs:186-205` | ephemeral XSTS cache | unchanged | no callers; if it ever gets one, the key must include the role (noted in a comment) |
| `xodus/src/tokens/device.rs:12` `:36` | `ensure_device_credentials`, `refresh_existing_device_credentials` | device | do not use an account |
| `xodus/src/auth.rs:70-187` | `do_sisu` (reads then rewrites the user STS, `:83`, `:149`) | unchanged (`store`) | only caller: an `#[ignore]` test; do not extend it (minimal diff) |
| `xodus/src/auth.rs:32` `:49` `:62` | `start_new_session`, `get_xsts_token`, `refresh_tokens` | n/a | do not touch the `TokenManager`, no callers |
| `xodus/src/licensing/content.rs:19` `:62` | `get_license_content`, `get_license_token` | `store` (via the caller) | receive the tokens as parameters |

### Service (`xodus-service`)

| Location | Function | Proposed role | Rationale |
|---|---|---|---|
| `xodus-service/src/main.rs:47-63` | `ensure_device_credentials` + device STS at startup | device | |
| `connection/xml.rs:52-138` (`:57` read, `:115` write) | `MsaTokenRequest` (XUser, `xgameruntime.dll`) | **`play`**, fallback `store`; the refreshed STS is written back to the role **actually read** | in-game identity; all game XSTS, cloud saves, achievements, presence derive from it |
| `connection/xml.rs:47` → `store_license.rs:57-99` (`:59` STS, `:60` account) | `StoreLicenseTokenRequest` (XStore: entitlements, DLC, receipts, package license) | **`store`** | On Windows, XStore uses the Microsoft Store account. The runtime does not send the XUID. See ambiguity A2. |
| `connection/xml.rs:43` → `store_updates.rs:282-333` (`:304`) | `StorePackageUpdatesRequest` (XSTS `update.xboxlive.com` → `GetBasePackage`) | **`store`** | package access = entitlement of the account that owns the game |
| `connection/proto.rs:4` | protobuf | n/a | `unimplemented!` |
| `connection/router.rs`, `simple_context.rs` | context | carry a shared `TokenManager`, no structural change | |

### CLI (`xodus-cli`)

| Location | Function | Proposed role | Rationale |
|---|---|---|---|
| `main.rs:273` | `TokenManager` construction | unchanged | |
| `main.rs:327-354` | `account [--json]` | `store` by default; `--account play`; optional `roles` field in JSON (see the design) | Nexus reads `stored` / `username` (`account-refresh.ts`) |
| `main.rs:358` + `commands/login.rs:13-79` (`:14` subscription cache, `:15` device, `:73` save) | `login` | `store` by default (Nexus, `externalAuth` unchanged); `--account play` | `play` does not clear the subscription cache |
| `main.rs:359` + `commands/logout.rs:4-15` | `logout [--device]` | see ambiguity A5 | |
| `license.rs:7-98` (`:13` device, `:19-21` account + STS) | `get_license` (content license, decryption keys) | **`store`** | called by `streaming` (`commands/streaming.rs:422`), `run` (`commands/run.rs:508`), `license`, `extract` |
| `license.rs:100-118` | `license_material` (device license) | device | |
| `package.rs:18-59` (`:23` device, `:27` STS) | `get_packages` (XSTS `update.xboxlive.com`) | **`store`** | `download` (`commands/download.rs:30`), `streaming` (`:145`) |
| `commands/library.rs:99-160` | `library` (entitlements `beige.xboxservices.com`) | **`store`** | library / Game Pass |
| `commands/subscription.rs:100-221` | `store_session`, subscription + cache | **`store`** | Game Pass |
| `commands/run.rs:27-37`, `:657-659` | `playfab_auth_header` → `XODUS_XSTS_PLAYFAB` passed to the game | **`play`** | PlayFab XSTS = player identity |
| `commands/run.rs:508` | `get_license` at launch | **`store`** | license |
| `commands/session.rs:16-84` | `prepare` (STS + device, "account-changed" check) | caller's role | generic helper |
| `commands/profile.rs:49-73` | `xbox_session` (XSTS `xboxlive.com`) | caller's role | helper |
| `commands/profile.rs:75-112` | `profile --json`: gamertag/gamerpic + subscription | **ambiguous (A1)**: gamertag `play`, subscription `store` | |
| `commands/game_activity.rs:61-104` | `game-activity` | **ambiguous (A1)** | player data |
| `commands/achievements.rs:89-128` | `achievements` | **ambiguous (A1)** | player data |
| `commands/clep.rs`, `splicense.rs`, `extract_eappx.rs`, `resolve-package`, `keyring-*` | | no account | |

## Ambiguous cases and open decisions

**A1 — `profile`, `achievements` and `game-activity` as seen by Nexus (decision required).**
Nexus rejects any response whose `account` differs from the `username` returned
by `account --json`: see `game-achievements.ts:19`, `game-activity.ts:42`,
`account-profile.ts:90` and `account-library.ts:22`. These commands are not
seen by the game, only by the Nexus UI.

- **Option A (recommended for phase 2)**: default `store`, behavior
  identical to today, plus `--account play` for terminal use.
  Nexus will display the gamertag and achievements of the `store` account,
  which is consistent with the account it shows.
- **Option B**: by default, gamertag, achievements and activity come from
  `play` when it is configured, but `account` keeps the `store` `username` so
  that Nexus accepts the response. An optional `playAccount` field is added.
  The format is unchanged, but the meaning of `account` changes. This is
  debatable for an upstream PR and fragile if Nexus evolves.

**A2 — XStore: the license receipt carries the `store` identity.**
`store_license.rs` puts the MSA ticket and the PUID of the `store` account in
`beneficiaries`. This is the Windows behavior (the Store issues with its own
account), so → `store`. Risk: a publisher that cross-checks, server-side, the
receipt beneficiary against the player's XUID (`play`) may refuse a DLC or a
currency. There is no fix on the Xodus side: Windows behaves the same way. It
is documented in the test plan.

**A3 — STS refreshed by `MsaTokenRequest`.** The effective role is resolved
**once** (`play` if it exists, otherwise `store`) and that role is the one
written to. In fallback, it is therefore the `store` STS that is refreshed,
exactly as today. A `play` session can never write to `store`. This choice
also avoids a race if `play` is signed in while a request is in
flight.

**A4 — PlayFab.** `XODUS_XSTS_PLAYFAB` is the player's PlayFab identity → `play`,
with fallback `store`.

**A5 — `logout` without options.** Proposal: behavior **strictly
identical** to today (`store` user + `device-tokens`, subscription
cache), and `play` is **kept**. Reasons: Nexus calls `logout`
for its own account. A Nexus sign-out that also cleared `play` would be
surprising. `play` alone grants access to nothing without `store`.
`logout --account play` removes only the `play/*` keys. It touches neither
the device nor the subscription cache. `--device` remains reserved for `store`.

**A6 — Account switch mid-game.** The service re-reads the keyring
on every request. A `login --account play` while a game is running will
switch the subsequent XUser requests. The game must be restarted after
configuring `play`.

**A7 — Local saves.** The runtime stores local saves under
`XodusGameSave\<xuid>\<scid>`. After switching to `play`, local saves
made so far with the `store` XUID will no longer be seen. They remain
in the prefix, and the game syncs the `play` cloud. This is expected, and
should be noted for the test.

**A8 — Blocker for phase 4 as described.** With an **external**
source, Nexus sets `linuxRunPatch: undefined` (`src/main/backend.ts:112`).
`gameLaunchArguments` then refuses to launch a game (`src/main/game-launch.ts:16`,
"Play requires the current managed Xodus backend"). With the external source
alone, you can install, but **not play**. Workaround without modifying
Nexus code: `readPointer()` only validates the JSON and `validate(binaryPath)`.
So `current.json` can be backed up, then a `current.json` can be written that
points to our build with `linuxRunPatch: "linux-run-v22"`. This touches Nexus
data (`~/.config/xodus-nexus/xodus-backends/`, path verified on
this machine), so it would only be done with the owner's approval.

**A9 — Shared keyring.** Nexus and the terminal CLI use the same
Secret Service service (`Xodus Service`) on the session bus. To verify in
phase 4: if Nexus starts its own keyring provider
(`keyring-session-stop`, `--provider-pid`), the terminal must see the same one.
In that case `xodus-cli login --account play` must be run while Nexus is running,
or after a `keyring-unlock`.

## Decisions (22.10.2026)

- **A1**: the backend keeps `store` as the default for `profile`, `achievements` and
  `game-activity`, so that upstream Nexus works without changes.
  `--account play` (with fallback) is added. It is the **Nexus fork** that
  will request `play` and bind the display to `account --account play`, like
  the Xbox app.
- **A5**: `logout` without options keeps the current behavior and keeps
  `play`. `logout --account play` removes only `play/*`.
- **A8**: go through the Nexus fork. The patch is added to its lock, and
  "Rebuild" produces a managed backend with the correct `linuxRunPatch`. No
  hacking of `current.json`.

## Implemented design (former title: "Proposed design for phase 2")

Commits on `dual-account`: `tokens: …`, `service: …`, `cli: …`.

**Model** (`xodus/src/tokens/manager.rs`)

- `pub enum AccountRole { Store (default), Play }`, exported by `xodus::tokens`.
- `TokenManager` carries a `role` field. `new()` gives `Store`, so **all
  existing callers are unchanged**.
  - `for_role(role)` returns the same storage, restricted to one role.
  - `resolve(role)` returns `Play` if a `play` account exists, otherwise `Store`.
    For `Store`, it always returns `Store`.
  - `has_user()` indicates whether an account is stored for the role.
- Keys: the `store` keys are unchanged. `play` uses
  `play/user-session`, `play/user-tokens` and `play/user-DA`. `dev_license` and
  `device-tokens` are shared.
- `remove_persistent()` in `Play` removes only the `play/*` keys. Device
  tokens are removed only by a `store` sign-out, as today.

**Service** (`xodus-service/src/connection/xml.rs`)

- `message_role()` is a pure, tested function:
  `MsaTokenRequest` → `Play`; `StoreLicenseTokenRequest` and
  `StorePackageUpdatesRequest` → `Store`.
- `parse_message` resolves the role once per request, then logs at
  `info` level: `message`, `role` and `fallback`, with no identifier or token.
- `MsaTokenRequest` reads the STS and writes the refreshed STS back **to the
  resolved role**. In fallback, that is therefore `store`, exactly as before.

**CLI**

| Command | Default (unchanged) | `--account play` |
|---|---|---|
| `login` | `store`; the subscription cache is cleared | signs in `play` only, the subscription cache is kept |
| `logout [--device]` | `store` + device tokens + cache; `play` kept | removes only `play/*`; rejects `--device` |
| `account [--json]` | strictly identical output | `{"role":"play"\|"store","fallback":bool,"stored":bool,"username"?}`: the account a game would use |
| `profile` | unchanged | gamertag/gamerpic from `play` (fallback `store`); the subscription always comes from `store` |
| `achievements`, `game-activity` | unchanged | `play` data (fallback `store`); `account` in the output = effective account |
| `run` | — | PlayFab XSTS (`XODUS_XSTS_PLAYFAB`) via `play`, with fallback; content license via `store` |
| `library`, `streaming`, `download`, `license`, `extract` | `store` | no option, always `store` |

`login --account play` goes through the same transport as `login`: the native
webview, or `--external-webview-stdio` driven by Nexus. **The binary built
like Nexus (`--no-default-features`) has no native webview.** From a
terminal, `login` therefore fails with "sign-in UI" unavailable. Signing in
the `play` account must be done through the Nexus fork. Alternative: a
diagnostic build with webview (`cargo build --release -p xodus-cli`, which
requires `webkit2gtk4.1-devel`, to be installed with sudo).

**Tests** (`xodus/src/tokens/dual_account_tests.rs`, `credential_` prefix so
they are run by `build-backend.mjs`; `xml.rs`: `store_and_play_message_roles`)

- legacy keys are preserved; role isolation;
- `play → store` fallback, including on `store` entries in the old format;
- `logout play` keeps `store` and the device; `logout store` keeps `play`;
- a refreshed `play` STS does not touch `store`; a refresh in
  fallback stays in `store` and does not create a `play` account.

**Xbox activity (fixed on 22.10.2026, unrelated to dual account)**: the
last-played date remained unavailable and the game page showed "Some Xbox activity
could not be retrieved". There were two causes.

- **Malformed titlehub request.** It used the `detail` decoration, which
  leaves `titleHistory` as `null`, and did not send an `Accept-Language`, which
  causes an HTTP 400. The request now uses the `titlehistory` decoration
  and sends the language.
- **Statistic without a value rejected.** userstats omits the `MinutesPlayed`
  value for a game with no recorded time. The parser treated this
  case as an error; it is now "no data".

`NEXUS_ACTIVITY_DIAGNOSTIC_V1 <stats|title>-<step> <HTTP status>` (stderr)
now indicates which read fails.

**Verification** (rustc 1.99.0)

- The full `cargo test` sequence from `build-backend.mjs`, plus
  `cargo test -p xodus`: all pass.
- `cargo clippy --all-targets`: 35 warnings before and after,
  identical. No new warnings.
- `rustfmt`: the added code is formatted. The files patched by Nexus were
  already not formatted; they were not reformatted.
- Release build: `--help` still exposes everything
  `parseBackendHelp`/`validate()`/`build-backend.mjs` expect, and
  `--account` is present on all six commands.

## Patch for Nexus

`scripts/dual-account-patch.sh` produces `xodus-dual-account.patch` from
`git diff nexus-base..dual-account -- crates`. This patch applies with
`git apply --check` then `git apply` after the 38 patches of the lock, and the
result is identical to `dual-account`. Entry to add **last** in
`patches`:

```json
{ "file": "xodus-dual-account.patch", "sha256": "f67a556fba4eb5ca6bd0466bb878d4d1a3aabe0aef7b534232960e2cc3b363b6" }
```

This is done in the Nexus fork, with `patchId` = `linux-run-v38-dual-account-N` (incremented with each new patch).
The `patchId` identifies the recipe. `compatibility` stays at
`linux-run-v22`, since the launch contract does not change. With this,
**Rebuild** builds a managed backend that can launch games.

The Nexus fork disables installing prebuilt backends (they do not have
the patch). It builds this backend via **"Use dual-account backend"**, and
**"Restore previous backend"** reverts to the previous backend.

## Updating when Nexus changes

1. `git -C xodus-nexus fetch upstream` and merge into the Nexus fork; read the
   new `assets/backend-source.lock.json`.
2. In `xodus-backend` (clean tree): `scripts/nexus-base.sh ../xodus-nexus nexus-base-next`.
   The script stops if a patch does not apply or if a sha256 differs.
3. `git rebase --onto nexus-base-next nexus-base dual-account`, then rename
   `nexus-base-next` to `nexus-base`. Conflicts are limited to the files
   listed above.
4. If the lock changes the Rust version: `rustup toolchain install <rust>`
   then `rustup override set <rust>`.
5. Rerun the tests (Verification section), then
   `scripts/dual-account-patch.sh` and carry the new sha256 over into the lock
   of the Nexus fork.

## Manual test plan (after Nexus integration)

1. Without a `play` account: everything behaves as before (`account --account play`
   reports `"fallback": true`).
2. Sign in `play` through the Nexus fork, then restart the game (see A6).
3. Reference game from the Nexus Compatibility wiki (Deep Rock Galactic, Gears
   of War: E-Day…):
   - installation via `store`;
   - launch;
   - in-game gamertag = `play`;
   - cloud saves and achievements of `play`.
4. The game log in Nexus must contain
   `Xodus account for MsaTokenRequest: play`, as well as `…: store` for
   `StoreLicenseTokenRequest` and `StorePackageUpdatesRequest`. Nexus starts the
   service with `XODUS_LOG=error,xodus_service::connection::xml=info` and keeps
   only these values. Do not use `scripts/send_msa_token_request.py`:
   it prints the received token.
5. Possible symptoms if a game cross-checks the Store against the player (A2):
   - DLC or paid content not recognized even though `store` owns it;
   - receipt or license failure mid-game;
   - missing virtual currency.

   Diagnosis: service logs (`Store license token request failed`,
   `hresult`), then compare with `logout --account play` (back to
   single-account mode). If the problem goes away, it is a publisher-side
   cross-check, and Windows would behave the same way.
6. Local saves created before switching to `play`: they are no longer
   visible (A7). This is expected, and the `play` cloud save
   takes over.
