# iccp-sim — ICCP / TASE.2 Server Simulator

A lightweight, config-driven **ICCP server simulator** (the *called* role) built on
[vendored copies](crates/) of the protocol crates from
[janfietz/telcon-tase2](https://github.com/janfietz/telcon-tase2) (MIT OR Apache-2.0).

Its purpose is **interoperability testing**: point a real ICCP/TASE.2 client
(e.g. OpenICCP) at this simulator and exercise association, name enumeration,
`TASE2_Version` / `Supported_Features` discovery, point reads, data-set transfer
sets, and condition-monitoring (COV) reports — without any real IED attached.

Everything the client sees (domain, Bilateral Table, version, features, points,
datasets, report traffic) is driven by a **JSON config file** — no recompile
needed to change the simulated plant.

```
┌────────────────┐   ICCP/TASE.2 over MMS    ┌─────────────────────────────┐
│ real ICCP      │  over ISO 8073 / TPKT     │ iccp-sim (this project)     │
│ client         │ ◄───────────────────────► │  • association (VMD/domain) │
│ (OpenICCP etc.)│        TCP :102           │  • GetNameList, Read/Write  │
└────────────────┘                           │  • DS transfer sets, COV    │
                                             └─────────────────────────────┘
```

---

## Workspace layout

```
sim/
├── Cargo.toml            # workspace root
├── config.example.json   # annotated example configuration
├── crates/
│   ├── mms-proto/        # MMS (ISO 9506) wire codec — TPKT/COTP/ACSE/BER
│   ├── tase2-proto/      # TASE.2 protocol types (points, datasets, reports)
│   └── tase2/            # async TASE.2 server/client on tokio
│       └── examples/     # simple_server / simple_client reference examples
└── sim/                  # the iccp-sim binary (config.rs, provider.rs, main.rs)
```

The two `sim`-specific vendored additions (marked `iccp-sim addition` in the
source) are:

1. `DataProvider::special_read()` — a default trait method for serving raw-shape
   TASE.2 variables (`TASE2_Version`, `Supported_Features`) that no upstream
   provider supplies.
2. A hook in `serve.rs::handle_read_with_manager` that consults `special_read`
   before falling through to the provider.

---

## Building

### Prerequisites

| What | Why |
|---|---|
| **Rust** (stable, ≥ 1.83) | compiler; install via [rustup](https://rustup.rs) |
| **Windows:** MSVC Build Tools 2022, "Desktop development with C++" workload | Rust's default `msvc` toolchain needs the MSVC linker (`link.exe`) |
| Internet (first build only) | cargo fetches crates.io dependencies (tokio, serde, …). All deps are pure Rust — no C/foreign-toolchain code |

Linux/macOS: a standard C/C++ linker (gcc/cc) is sufficient instead of MSVC.

### Commands

```powershell
# debug build (fast compile)
cargo build
# binary: target\debug\iccp-sim.exe   (Windows) / target/debug/iccp-sim (unix)

# release build (smaller, faster binary — recommended for deployment)
cargo build --release
# binary: target\release\iccp-sim.exe

# run the vendored protocol-crate test suite
cargo test -p tase2
```

> **Windows tip:** if a running `iccp-sim.exe` is holding the binary, the
> rebuild fails with `Access is denied` — stop the simulator process first.

### Offline build (air-gapped machine)

The binary itself is fully self-contained — you can just copy
`iccp-sim.exe` + a config file. To *rebuild* on an offline machine, vendor the
dependencies on an internet-connected machine:

```powershell
cargo vendor vendor          # creates vendor/ + vendor/.cargo/config.toml
```

Copy the whole workspace (source + `vendor/` + `Cargo.lock`) to the target,
move the source-replacement config to the workspace root (adjust the relative
paths from `../vendor/...` to `vendor/...`), then:

```powershell
cargo build --offline
```

---

## Running

```
iccp-sim -c config.json
iccp-sim --config config.json --port 2404      # override port from config
iccp-sim config.json                           # bare positional also works
```

| Option | Meaning |
|---|---|
| `-c`, `--config <file>` | JSON config (required unless a bare positional path is given) |
| `--port <port>` | Override the `port` field in the config |

Logging goes to stderr via `tracing`; set `RUST_LOG` to tune verbosity
(default `info`), e.g. `RUST_LOG=debug iccp-sim -c config.json`.

### Starting an OpenICCP client against it

1. Start the simulator: `iccp-sim.exe -c config.json`
   (listen address and port come from the config, e.g. `127.0.0.1:102`).
2. In your ICCP client, create a TASE.2 server connection to
   `<simulator-ip>:102` with the domain from the config (`ICC1` in the example).
3. The client should associate, enumerate the domain, read `TASE2_Version` and
   `Supported_Features`, list points/datasets, and (if it claims a data-set
   transfer set) start receiving OBJECT_CHANGE reports at the configured
   mutation interval.

### Quick self-test without a real client

The vendored crate ships a loopback client example you can use for a smoke test
(it expects exactly the `config.example.json` profile: domain `ICC1`, `P1`
discrete 10, `P2` 20, dataset `DS1`):

```powershell
# terminal 1
cargo run -p tase2 --example simple_server    # or just run iccp-sim

# terminal 2
cargo run -p tase2 --example simple_client
# expect: P1 = Discrete(10), a few InformationReports, then clean release
```

---

## Configuration reference

Full working example: [`config.example.json`](config.example.json).
Unknown fields are rejected (typo protection). All values below are
placeholders — set them to match your test setup.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `domain` | string | `"ICC1"` | MMS domain the client associates to (OpenICCP domain name) |
| `ip` | string | `"0.0.0.0"` | IPv4 address to bind (`0.0.0.0` = all interfaces; use a specific NIC address to restrict) |
| `port` | int | `102` | TCP port (port 102 may need elevation/admin on some OSes; use another if not) |
| `bilateral_table_id` | string | `"BLT1"` | Identifier served as `Bilateral_Table_ID` |
| `tase2_version.major` / `.minor` | int | `1` / `0` | `TASE2_Version` served to the client |
| `supported_features` | string[] | all four | Any of: `"ds_transfer"`, `"cov"`, `"device_control"`, `"bilateral_access"` |
| `access.domain_read` | bool | `true` | All domain points readable |
| `access.domain_read_write` | bool | `false` | All domain points writable |
| `access.dataset_ops` | bool | `true` | Allow CREATE/DELETE data-set operations |
| `access.points` | map | `{}` | Per-point override: `{"P1": "read_write" \| "read_only" \| "none"}` |
| `points[]` | array | `[]` | Simulated points (see below) |
| `datasets[]` | array | `[]` | Data sets (see below) |
| `mutation.interval_secs` | int | `0` | Seconds between value steps; `0` disables the self-mutation loop |
| `mutation.points[]` | array | `[]` | Points cycled through `values` (see below) |

### Points

```json
{ "name": "P1", "kind": "discrete", "initial": 10 }
```

`kind` = `{real|discrete|state}` optionally suffixed with `_q`, `_q_time_tag`,
`_extended`, or `_q_time_tag_extended` (e.g. `discrete_q_time_tag`,
`state_q_time_tag_extended`).

`initial` is interpreted per kind:

- `real*` → number (f32)
- `discrete*` → integer
- `state*` → `"between"` / `"closed"` / `"tripped"` / `"invalid"` or `0`..`3`

### Datasets

```json
{ "name": "DS1", "members": ["P1", "P2"] }
```

Members must be point names from `points`. The four ICCP control members
(`Transfer_Set_Name`, `Transfer_Set_Time_Stamp`, `DSConditions_Detected`,
`Event_Code_Detected`) are **prepended automatically** — do not list them.

### Mutation (drives COV / OBJECT_CHANGE reports)

```json
"mutation": {
  "interval_secs": 2,
  "points": [
    { "name": "P1", "values": [10, 0, 10] },
    { "name": "P2", "values": [20, 0, 20] }
  ]
}
```

Every `interval_secs`, each listed point advances one step through `values`
(wrapping). Each step writes the new value and notifies the transfer-set
manager, so any client transfer set on a dataset containing that point emits an
OBJECT_CHANGE Information Report. An empty `values` list is rejected at startup.

---

## Interoperability tuning (no recompile)

If a real client rejects the association or handshake, the first things to
adjust in the JSON are:

- `tase2_version` — try `{ "major": 0, "minor": 2 }` variants
- `supported_features` — subset or superset of the four bits
- `bilateral_table_id` — some clients expect a specific table id

Server-side tracing (`RUST_LOG=debug`) shows the association state machine and
per-connection read/write activity for diagnosis.

## License

MIT OR Apache-2.0 — same as the vendored upstream
[janfietz/telcon-tase2](https://github.com/janfietz/telcon-tase2).
