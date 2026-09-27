# Deploying GuardLayer

How to run GuardLayer in production: which shape to pick, how to size it, and the settings that matter.
The numbers come from [`benchmarks/perf.py`](https://github.com/Lijithvmv/Guard-Layer/blob/main/benchmarks/perf.py). Re-run it on your own hardware before you size anything
([Performance](#performance)).

## 1. Pick a shape

| Shape | When | Latency added | Notes |
|---|---|---|---|
| **In-process library** (recommended) | Python apps and agents | Scan time only | No network hop, no extra service to secure. Session taint and the audit log live with the app |
| **Sidecar** (REST API in the same pod) | Non-Python apps; one guard per app | Scan time + a loopback HTTP call | Bind to `127.0.0.1`; sessions stay with the one app |
| **Internal service** (REST API behind a Service) | Many apps, one central policy | Scan time + network | Needs session affinity or a shared session store (see [Sessions](#4-sessions-across-processes)) |
| **Agent hook** (Claude Code) | Coding agents on laptops | Process start per check (~0.3 s: import + build, measured) | `guardlayer hook claude-code --print-config`; uses the file session store |

Never expose the REST API to the internet. It's a policy engine for your own services, not a public endpoint.

## 2. Container

```bash
docker build -t guardlayer .
docker run -p 127.0.0.1:8000:8000 -e GUARDLAYER_API_KEY=change-me --read-only --tmpfs /tmp guardlayer
```

The image runs as a non-root user (uid 10001), writes nothing outside `/tmp` and `/var/log/guardlayer`, and includes a healthcheck
on `/health`. [`deploy/docker-compose.yml`](https://github.com/Lijithvmv/Guard-Layer/blob/main/deploy/docker-compose.yml) adds a read-only root filesystem, dropped capabilities,
`no-new-privileges`, a memory limit, a config file and a volume for the audit log. It uses inline `configs`, which need
Docker Compose 2.23 or later.

| Variable | Purpose |
|---|---|
| `GUARDLAYER_API_KEY` | Required outside localhost. Every `/v1` call must send `X-API-Key` (compared in constant time) |
| `GUARDLAYER_CONFIG` | Path to the TOML/JSON config |
| `GUARDLAYER_PRESET`, `GUARDLAYER_MODE`, `GUARDLAYER_FAIL_CLOSED`, ... | Override the config file (see [Configuration](https://github.com/Lijithvmv/Guard-Layer/blob/main/README.md#configuration)) |
| `WEB_CONCURRENCY` | uvicorn worker processes (default 1) |

## 3. Kubernetes

[`deploy/kubernetes/guardlayer.yaml`](https://github.com/Lijithvmv/Guard-Layer/blob/main/deploy/kubernetes/guardlayer.yaml) (with a `kustomization.yaml`) contains a ConfigMap,
Deployment, Service, NetworkPolicy, HorizontalPodAutoscaler and PodDisruptionBudget.

```bash
kubectl create namespace guardlayer
kubectl -n guardlayer create secret generic guardlayer-api --from-literal=api-key="$(openssl rand -hex 32)"
kubectl -n guardlayer apply -k deploy/kubernetes/
```

What it sets and why:

- **Hardening.** Non-root, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, no service-account
  token (GuardLayer never calls the Kubernetes API).
- **Network.** A ClusterIP Service only. The NetworkPolicy admits callers labelled `guardlayer-client: "true"` and allows **no
  egress**: the core engine needs no network at all. Open DNS and your model host only if you enable an LLM judge, or allow
  a download of the classifier (better: bake the model into the image).
- **One worker per pod, scale with replicas.** Python runs one scan per core at a time, so throughput comes from processes. The
  HPA scales on CPU (70%). There is no CPU limit because throttling adds tail latency; the memory limit stays.
- **Resources.** Requests `250m` CPU / `128Mi`, limit `256Mi`. A worker measured ~55 MB resident after repeated 48,000-character
  scans. With the classifier (`ml` extra) plan on ~1.5 GiB per pod and a longer startup probe.
- **Probes.** A startup probe (up to 60 s), then readiness and liveness on `/health`.
- **Availability.** Two replicas minimum, spread across nodes, a PodDisruptionBudget, and rolling updates with zero unavailable.

The manifests pass strict schema validation against Kubernetes 1.31 (`kubernetes-validate --strict`), but the maintainer hasn't run them on a live cluster.
Adapt image names, labels and storage to your platform.

## 4. Sessions across processes

Session taint (the `trifecta`, `sensitive_data_egress` and `after_injection` rules) needs every check in one conversation to see
the same session state.

- **One process** (library, sidecar, single worker): the default memory store is enough.
- **Several workers or replicas**: either route each conversation to the same pod (session affinity on your gateway, keyed on
  the session ID), or use `[session] store = "file"` with `dir` on a volume every process can reach (ReadWriteMany in
  Kubernetes). The file store locks and merges per session, so concurrent writers don't lose each other's taint.

If neither holds, a conversation that lands on two pods is judged with partial history. Taint only ever *adds* restrictions, so
this fails toward fewer blocks, not wrong blocks. It's still a gap: the trifecta rule can't fire if its three parts land on
different pods.

## 5. Audit log and evidence

- **One writer per file.** Two processes appending to one file fork the hash chain. Put `{hostname}` (the pod name in Kubernetes)
  and, with more than one worker, `{pid}` in `[audit] path`: `"/var/log/guardlayer/audit-{hostname}-{pid}.jsonl"`.
- **Keep it.** An `emptyDir` disappears with the pod. For evidence you need later, mount durable storage or ship the files with
  your log agent. Record each file's head hash (`guardlayer audit verify`) somewhere separate, so truncation is detectable.
- **Sign it.** Mount an Ed25519 key from a Secret and set `signing_key` (needs the `signing` extra). Keep the public key with
  your auditors.
- **Export it.** `guardlayer evidence export <file> --format csv` produces the control-mapped evidence pack per file
  (see [Compliance evidence](https://github.com/Lijithvmv/Guard-Layer/blob/main/README.md#compliance-evidence)).

## 6. Rollout

1. Start in **observe** mode (`preset = "observe"`): nothing is blocked, and every result carries the `shadow_verdict`.
2. Review what would have been flagged or blocked on real traffic; tune `disabled_rules`, allow-lists and thresholds.
3. Switch to `balanced`, rule by rule if needed. Use `strict` or `airgap` for agents with sensitive access.
4. Decide fail-open versus fail-closed: `balanced` lets text through if a scanner errors; `strict` and `airgap` block it.

## Performance

Measured on 2026-09-27 on a laptop (Intel Core i5-9300H, 4 cores / 8 threads, Windows 11, Python 3.13), default `balanced`
configuration, no classifier. Raw results: [`benchmarks/results/`](https://github.com/Lijithvmv/Guard-Layer/tree/main/benchmarks/results/). Reproduce with
`python benchmarks/perf.py`. Laptop numbers vary by about 15% between runs (turbo and thermals); expect a server core to be
faster.

**Per call (in-process, one thread):**

| Edge | Payload | p50 | p95 |
|---|---|---|---|
| `scan_tool_call` | shell command | **0.23 ms** | 0.33 ms |
| `scan_tool_call` | HTTP POST, 4,000-char body (with or without session taint) | 13 ms | 15 ms |
| `scan_input` | 200 chars (a typical chat turn) | **1.4 ms** | 1.6 ms |
| `scan_input` | 1,000 chars | 13 ms | 14 ms |
| `scan_input` | 4,000 chars | 52 ms | 56 ms |
| `scan_input` | 16,000 chars | 167 ms | 172 ms |
| `scan_input` | 48,000 chars (near the 50,000 default limit) | 403 ms | 415 ms |
| `scan_output` | 500 / 4,000 / 16,000 chars, with system-prompt leak check | 1.4 / 10 / 40 ms | 1.5 / 11 / 42 ms |
| `scan_context` | RAG chunk, 2,000 / 8,000 chars | 29 / 115 ms | 34 / 122 ms |
| `scan_tool_result` | 8,000 chars of JSON rows | 48 ms | 55 ms |

**Throughput** (1,000-char inputs): 78 scans/s with 1 process, 135 with 2, 192 with 4, 234 with 8 (hyper-threads add little).

**REST API** (uvicorn, 1,000-char payloads, load generator on the same machine, so these understate a dedicated host):

| Workers | Clients | `/v1/scan/input` | `/v1/scan/tool-call` |
|---|---|---|---|
| 1 | 8 | 67 req/s, p50 117 ms, p95 163 ms | 208 req/s, p50 38 ms, p95 48 ms |
| 4 | 16 | 133 req/s, p50 87 ms, p95 162 ms | 435 req/s, p50 29 ms, p95 47 ms |

API latencies include queueing: with more clients than workers, requests wait. Size for your peak concurrency, not the average.

**Memory:** the guard's own objects take ~1.7 MB; scanning 48,000 characters allocates ~4 MB at peak; a library process peaked
at ~52 MB resident, an API worker at ~55 MB. Import takes ~0.16 s and building the guard ~0.11 s.

**How to read this:**

- **Cost grows with text length**, at roughly 10–13 ms per 1,000 characters for inputs and context. The two biggest costs are the
  signature rules (run on the raw text and its de-obfuscated views) and the similarity scanner (which compares overlapping
  sentence windows against the attack corpus). Output scanning is cheaper because similarity doesn't run on it.
- **Tool calls are the cheap, critical edge:** a shell command is checked in about a quarter of a millisecond. Large request
  bodies cost more because their text is scanned for secrets and injections.
- **Against an LLM call** (typically 0.5–10 s), a 1,000-character guard check adds well under 3% to the round trip.
- **To go faster:** scan retrieved content at chunk size (1–2 KB) rather than whole documents; lower
  `[scanners.similarity] max_windows` (default 256) to trade coverage of very long texts for speed; run one process per core.
- **The classifier is the expensive option:** ~150 ms per short prompt on CPU (see [Evaluation](https://github.com/Lijithvmv/Guard-Layer/blob/main/README.md#evaluation)). Use a
  GPU or reserve it for high-risk routes.
