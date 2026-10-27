# cortex9-effect-attest

[![CI](https://github.com/federiconbaez/cortex9-effect-attest/actions/workflows/ci.yml/badge.svg)](https://github.com/federiconbaez/cortex9-effect-attest/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-Apache--2.0-blue)

Atestación firmada de los efectos que el kernel observa en cada `tools/call` de MCP: qué ejecutó, qué abrió para escribir y a dónde se conectó **ese** request, atribuido por cgroup v2 y firmado como statement in-toto dentro de un sobre DSSE (Ed25519).

Signed attestation of the effects the kernel observes for each MCP `tools/call`: what **that** request executed, opened for writing and connected to, attributed by cgroup v2 and signed as an in-toto statement inside a DSSE envelope (Ed25519).

> **ES** primero · **EN** below

---

## ES

### Problema

Cuando un agente llama a una tool, lo único que queda es lo que la tool dice que hizo. Las herramientas eBPF de seguridad (por ejemplo Tetragon) observan exec, syscalls y acceso a archivos y red, pero los atribuyen a procesos, contenedores o pods, no a un request MCP, y emiten eventos, no atestaciones firmadas. En la propuesta de MCP "Tool Outcome Attestation" (issue #3350, cerrada) es el propio servidor el que firma el resultado; en la discusión se señala que eso atestigua lo que el servidor *dice* del efecto, no que el efecto ocurrió.

### Qué hace

```
cliente MCP ──stdio──► effect-attest serve
                         │ tools/call #N
                         ├─ mkdir /sys/fs/cgroup/effect-attest/call-<pid>-<n>
                         ├─ registra el cgroup id en el mapa CALL_CGROUPS
                         ├─ fork → el hijo escribe "0" en cgroup.procs → execve(tool)
                         ├─ espera al proceso y a que el cgroup quede vacío
                         │   (descendientes y daemons con doble fork incluidos)
                         ├─ drena el ring buffer → efectos de ESE cgroup
                         └─ statement in-toto v1 → DSSE (PAE + Ed25519) → result._meta
kernel: raw_syscalls/sys_enter + sys_exit (aya)
        filtro en kernel por bpf_get_current_cgroup_id()
        execve/execveat, open/openat/openat2/creat con intención de escritura, connect
```

- **Atribución:** cada call corre en su propio cgroup v2. El programa eBPF descarta en el kernel todo lo que no viene de un cgroup registrado; userspace enruta cada registro por cgroup id. Hijos, threads, `sh -c` y daemons con `setsid` + doble fork heredan el cgroup.
- **Efectos:** `exec` (path pasado a execve/execveat), `open_write` (open/openat/openat2/creat con `O_WRONLY|O_RDWR|O_CREAT|O_TRUNC`; las aperturas de sólo lectura se descartan en el kernel) y `connect` (sockaddr decodificado: IPv4, IPv6, unix). Cada efecto lleva el valor de retorno, pid/tid, comm y timestamp.
- **Statement:** `_type` `https://in-toto.io/Statement/v1`, dos subjects con digest sha256 (el request: tool + arguments + id; y el result devuelto sin `_meta`), y un predicate propio (`.../predicate/mcp-call-effects/v0.1`) con observer, call, effects e integrity (`cgroup_drained`, `ring_drops_during_call`, `incomplete_targets`).
- **Sobre:** DSSE v1: la firma cubre `PAE(payloadType, payload)`; `payloadType` `application/vnd.in-toto+json`; keyid = sha256 de la clave pública. El verificador acepta base64 estándar y URL-safe y devuelve los mismos bytes que verificó.
- **Verificador:** `effect-attest verify --pubkey K.pub [--require-complete] archivo...`.

### Uso

```sh
# eBPF (nightly + rust-src + bpf-linker 0.12)
(cd effect-attest-ebpf && cargo build --release)
cargo build --release

./target/release/effect-attest keygen --out ./signer          # signer.key (0600) + signer.pub
cat > tools.json <<'JSON'
{"tools": [{"name": "sh", "command": ["/bin/sh", "-c"], "timeout_ms": 10000}]}
JSON
sudo ./target/release/effect-attest serve --catalog tools.json --key signer.key \
  --bpf-object effect-attest-ebpf/target/bpfel-unknown-none/release/effect-attest-ebpf \
  --attest-dir ./attestations
# {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sh","arguments":{"args":["echo hi > /tmp/x"]}}}

./target/release/effect-attest verify --pubkey signer.pub --require-complete --print attestations/*.dsse.json
```

Sin el objeto eBPF o sin privilegios, `serve` en modo atestado **falla** con `BPF did not load`; no hay degradación silenciosa. `--unattested` corre las tools sin observar ni firmar nada (y lo avisa por stderr y en `initialize`).

### Medición (criterio de aceptación)

Criterio: con 50 tools de efectos conocidos, ≥ 99 % de los efectos (exec / open-write / connect) presentes en la atestación firmada y 0 atribuciones cruzadas entre calls concurrentes.

`effect-attest bench` genera 50 tools en 6 patrones (directo, fork, thread, `sh -c`, daemon con doble fork que actúa 150 ms después de que el proceso principal terminó, y variantes creat/openat2/execveat/IPv6), lanza las 50 `tools/call` a la vez por una sesión MCP real sobre stdio, verifica cada sobre (firma, tipo, subject del request y del result, `--require-complete`) y compara los efectos firmados con la verdad de terreno. Cada ronda usa paths y puertos nuevos, y cada path o dirección codifica (ronda, tool): un efecto en la atestación equivocada se cuenta como atribución cruzada (hay un test que verifica que el detector la encuentra).

Comando:

```sh
sudo ./target/release/effect-attest bench --tools 50 --rounds 10 --baseline \
  --bpf-object effect-attest-ebpf/target/bpfel-unknown-none/release/effect-attest-ebpf --out report.json
```

Resultado medido en una máquina de desarrollo (x86_64, kernel 6.12, como root, 2026-10-27):

| métrica | valor |
|---|---|
| calls | 500 (50 tools × 10 rondas, 50 concurrentes) |
| efectos esperados / encontrados | 2580 / 2580 (**100 %**) |
| atribuciones cruzadas | **0** |
| sobres que no verifican / cgroups sin drenar | 0 / 0 |
| verificación offline por sobre | p50 51 µs, p99 101 µs |
| latencia `tools/call` atestada | p50 120 ms, p99 285 ms |
| misma carga sin atestación (`--unattested`) | p50 22 ms, p99 48 ms |

El job `attest` del CI corre los tests de kernel y el mismo bench con `sudo` en el kernel real del runner de GitHub y **falla** si BPF no carga o si no se cumple el criterio. El reporte JSON queda como artifact `bench-report`.

### Qué está probado y qué no

Probado:
- Formato DSSE contra el vector de test de la especificación (PAE), y rechazo de payload alterado, tipo alterado, clave equivocada y `payloadType` no soportado.
- Carga real del programa eBPF (verificador del kernel) y atribución por cgroup con 50 calls concurrentes, incluyendo hijos, threads, shell y daemons, en la máquina de desarrollo; en CI, en el runner de GitHub (ver el job `attest`).
- Que una apertura de sólo lectura no aparece en la atestación.

No probado / límites conocidos:
- **Overhead:** la meta de la idea era < 5 % en p99 y **no se cumple**: la latencia de una call atestada es varias veces la de una sin atestar, porque se crea y se borra un cgroup por call y, sobre todo, porque la call espera a que terminen todos sus descendientes (por diseño: es lo que hace atribuibles los efectos de un daemon). No medí el costo en syscalls/s del resto del host.
- **Cobertura de syscalls:** sólo exec, open con intención de escritura y connect. No ve `write` sobre fds heredados, `mmap`, `rename`/`unlink`/`chmod`, `sendto`/`sendmsg` sin `connect`, ni operaciones hechas con **io_uring** (no pasan por los tracepoints de syscalls).
- **Escape del cgroup:** un proceso con privilegios para moverse de cgroup, o una tool que le pide a otro servicio (systemd, dbus, docker) que haga el trabajo, deja efectos fuera de la atribución. Lo mismo con sub-cgroups creados por la tool: se atribuye por el cgroup actual exacto, no por ancestro.
- **TOCTOU:** el path y el sockaddr se leen de memoria de usuario al entrar a la syscall; otro thread puede cambiar el buffer después. Paths de más de 255 bytes se truncan y se marcan `target_incomplete`; si la página no está residente la lectura falla y también se marca.
- **Paths relativos** se registran tal cual con su `dirfd`, sin resolver. PIDs del namespace inicial.
- **Modelo de amenaza:** la clave de firma vive en el mismo host que el servidor y el colector. La atestación protege contra una tool (o un servidor sin privilegios de root) que miente sobre lo que hizo; **no** protege contra root en el host, que puede descargar el programa o firmar lo que quiera. Sin TEE, sin Sigstore/Rekor.
- `ring_drops_during_call` es un contador global del host (conservador): cualquier drop durante la call la marca como incompleta.
- La forma canónica de los digests de subject es JSON con claves ordenadas de `serde_json`, no RFC 8785.
- Sólo x86_64 probado; la tabla de aarch64 está escrita pero no se ejecutó.

### Fuentes leídas

- in-toto Attestation Framework, Statement v1: <https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md>
- DSSE protocol y envelope v1.0.2: <https://github.com/secure-systems-lab/dsse/blob/master/protocol.md>, <https://github.com/secure-systems-lab/dsse/blob/master/envelope.md>
- MCP SEP "Tool Outcome Attestation" (cerrada): <https://github.com/modelcontextprotocol/modelcontextprotocol/issues/3350>
- Tetragon README: <https://github.com/cilium/tetragon>

Basado en [cortex9-ebpf-tracer](https://github.com/federiconbaez/cortex9-ebpf-tracer) (estructura aya, tracepoints `raw_syscalls`) y [mcp-server-rs](https://github.com/federiconbaez/mcp-server-rs) (JSON-RPC 2.0 sobre stdio); el código se copió y adaptó, esos repos no cambian.

---

## EN

### Problem

When an agent calls a tool, all that is left is what the tool says it did. eBPF security tools (Tetragon, for example) observe exec, syscalls and file/network access, but attribute them to processes, containers or pods, not to an MCP request, and they emit events, not signed attestations. In the MCP "Tool Outcome Attestation" proposal (issue #3350, closed) the server signs its own result; the discussion there points out that this attests what the server *claims* about the effect, not that the effect happened.

### What it does

- **Attribution:** every call runs in its own cgroup v2. The eBPF program drops in-kernel anything not coming from a registered cgroup; userspace routes each record by cgroup id. Children, threads, `sh -c` and `setsid` + double-fork daemons inherit the cgroup.
- **Effects:** `exec` (path passed to execve/execveat), `open_write` (open/openat/openat2/creat with `O_WRONLY|O_RDWR|O_CREAT|O_TRUNC`; read-only opens are dropped in the kernel) and `connect` (decoded sockaddr: IPv4, IPv6, unix), each with return value, pid/tid, comm and timestamp.
- **Statement:** in-toto Statement v1 with two sha256 subjects (the request: tool + arguments + id; the returned result without `_meta`) and a project-defined predicate (observer, call, effects, integrity).
- **Envelope:** DSSE v1, signature over `PAE(payloadType, payload)`, `application/vnd.in-toto+json`, Ed25519; the verifier accepts standard and URL-safe base64 and returns the exact bytes it verified.
- **Verifier:** `effect-attest verify --pubkey K.pub [--require-complete] file...`.

See the Spanish section for the usage example. In attested mode `serve` **fails** with `BPF did not load` when it cannot load the program; `--unattested` runs tools without observing or signing (and says so).

### Measurement

Criterion: over 50 tools with known effects, ≥ 99 % of effects (exec / open-write / connect) in the signed attestation and 0 cross-call misattributions under concurrency.

```sh
sudo ./target/release/effect-attest bench --tools 50 --rounds 10 --baseline \
  --bpf-object effect-attest-ebpf/target/bpfel-unknown-none/release/effect-attest-ebpf --out report.json
```

Measured on a development machine (x86_64, kernel 6.12, root, 2026-10-27): 500 calls (50 tools × 10 rounds, 50 concurrent), **2580 / 2580 effects (100 %)**, **0 misattributions**, 0 failed verifications, 0 undrained cgroups; offline verification p50 51 µs / p99 101 µs per envelope; attested call latency p50 120 ms / p99 285 ms vs 22 / 48 ms unattested.

The CI `attest` job runs the kernel tests and the same bench with `sudo` on the GitHub runner's real kernel and **fails** if BPF does not load or the criterion is not met; the JSON report is uploaded as the `bench-report` artifact.

### Tested and not tested

Tested: DSSE against the spec's PAE test vector and rejection of tampered payload/type, wrong key and unsupported type; real eBPF loading and cgroup attribution with 50 concurrent calls (children, threads, shell, daemons); read-only opens are not reported.

Not tested / known limits:
- **Overhead:** the idea's < 5 % p99 target is **not met**: an attested call takes several times longer, because of per-call cgroup setup/teardown and, mainly, because the call waits for all descendants (by design). Host-wide syscall throughput was not measured.
- **Syscall coverage:** only exec, write-intent opens and connect. No `write` on inherited fds, `mmap`, `rename`/`unlink`/`chmod`, `sendto`/`sendmsg` without `connect`, and nothing done through **io_uring**.
- **Cgroup escape:** a process privileged enough to change cgroup, or a tool that asks another service (systemd, dbus, docker) to act, is not attributed. Sub-cgroups created by the tool are not followed (exact cgroup match, not ancestor).
- **TOCTOU:** paths and sockaddrs are read from user memory at syscall entry; another thread can change the buffer afterwards. Paths over 255 bytes are truncated and flagged `target_incomplete`, as are failed reads of non-resident pages.
- Relative paths are recorded as-is with their `dirfd`. PIDs are init-namespace PIDs.
- **Threat model:** the signing key lives on the same host as the server and collector. This protects against a tool (or a non-root server) lying about what it did; it does **not** protect against root on the host. No TEE, no Sigstore/Rekor.
- `ring_drops_during_call` is a host-wide counter (conservative).
- Subject digests use `serde_json` sorted-key JSON, not RFC 8785.
- Only x86_64 tested; the aarch64 table exists but was never run.

### Sources read

Listed in the Spanish section (in-toto Statement v1, DSSE protocol/envelope, MCP issue #3350, Tetragon README). Builds on cortex9-ebpf-tracer and mcp-server-rs by copying and adapting code; those repos are unchanged.

## License

Apache-2.0. The eBPF object declares `GPL` as its kernel license, which the kernel requires for the helpers it uses.
