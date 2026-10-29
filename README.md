# iouring-policy-cbpf

Compilador en Rust de políticas declarativas de **io_uring** a **cBPF**, listo para
`IORING_REGISTER_BPF_FILTER` (Linux ≥ 7.0, merge `591beb0`).

*Rust compiler from declarative io_uring policies to classic BPF, aimed at
`IORING_REGISTER_BPF_FILTER` (Linux ≥ 7.0, merge `591beb0`).*

## Qué problema resuelve / Problem

Desde Linux 7.0 el kernel acepta filtros cBPF por opcode. Escribir cBPF a mano
es frágil; runtimes (youki/crun) embeben prototipos, pero no hay un crate
reutilizable que tome un JSON estilo
[iouring-lab `profile/default.json`](https://github.com/gvozdetsky/iouring-lab)
y emita bytecode verificable.

*Linux 7.0 accepts per-opcode cBPF filters. Hand-written cBPF is fragile;
runtimes embed prototypes, but there is no reusable crate that takes an
iouring-lab-shaped JSON profile and emits testable bytecode.*

## Qué está probado en esta box / Proven on this box

| Cosa | Estado |
|------|--------|
| Parser del JSON OCI-like | sí (`cargo test`) |
| Emisión cBPF + intérprete userspace | sí |
| Cobertura del `default.json` (38 allow + denies) | **medida** (ver abajo) |
| `IORING_REGISTER_BPF_FILTER` en el kernel | **no** — kernel 6.12; el binario `iouring-policy-enforce` **falla fuerte** (exit 2) |

*Unit tests and the userspace interpreter run here. Real kernel registration
needs Linux ≥ 7.0 and is exercised by the `enforce.yml` workflow, which fails hard
(no `continue-on-error`, no silent skip) when the feature is missing.*

## Medición / Measurement

Perfil: `fixtures/default.json` (copia del de iouring-lab, 38 opcodes en allow,
`defaultAction=deny`, `deniedSqeFlags=[IOSQE_BUFFER_SELECT, IOSQE_FIXED_FILE]`,
`socketFamilies=[AF_UNIX, AF_INET, AF_INET6]`).

```bash
cargo run --quiet -- measure fixtures/default.json
```

Resultado medido en esta box (2026-10-27):

```text
allow=38/38 deny=27/27 perfect=true
```

(65 opcodes totales = `IORING_OP_LAST`; 38 allow + 27 deny por `DENY_REST`.)

Comando que lo reproduce: el de arriba. También:

```bash
cargo test --test coverage_lab -- --nocapture
```

## Enforcement (VM / CI, no la box)

```bash
cargo run --bin iouring-policy-enforce
# en 6.12 → exit 2 con mensaje claro
# en >= 7.0 con la feature → exit 0
```

El workflow `.github/workflows/enforce.yml` corre exactamente eso y **no**
tiene `continue-on-error`.

## Uso / Usage

```bash
cargo run -- compile fixtures/default.json --dump
cargo run -- measure fixtures/default.json
cargo run -- register fixtures/default.json   # falla fuerte sin kernel 7+
```

## CI

- `.github/workflows/ci.yml`: fmt + `clippy -D warnings` + `cargo test` + reproducción de la medición. Tiene que quedar verde.
- `.github/workflows/enforce.yml`: corre `cargo run --bin iouring-policy-enforce` de verdad en el runner, sin `continue-on-error` ni `#[ignore]`. En runners con kernel < 7.0 este workflow queda **rojo** (exit 2): es el resultado esperado y honesto, no un skip.

## Fuentes leídas de verdad / Sources actually read

- Kernel merge `591beb0e3a03258ef9c01893a5209845799a7c33` (uapi
  `io_uring/bpf_filter.h`, `io_uring_bpf_ctx`, `IO_URING_BPF_FILTER_DENY_REST`)
- LWN 1054225 (task-level io_uring restrictions)
- man `io_uring_register_bpf_filter*`
- OCI runtime-spec#1323 (`linux.ioUring`)
- gvozdetsky/iouring-lab `profile/default.json`
- youki#3805 (prototipo embebido, no crate)

## Fuera de alcance / Out of scope

Integración en runc/youki/crun, patch del kernel, `RestrictIOUring=` en systemd.
El follow-up natural es el consumo del perfil desde systemd (#44) y el shim de
`IORING_REGISTER_PROBE` (#45).

## Licencia

Apache-2.0. Copyright 2026 Federico Nicolas Báez Rizzo.
