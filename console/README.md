# Campus SOC Console

A single-page React + Vite + Tailwind app that gives the stack a modern, dark SIEM-style console. It replaces the two ad-hoc HTML dashboards in `collector/static/` and `simulator/static/` with one unified UI.

## What it shows

- **Dashboard** — live counters from `GET /summary` (audit), a stacked time-series of actions (15m / 1h / 24h / all), recent decision cards, OSINT / policy-rule / LLM-provider / scenario distributions. Auto-updates via SSE (`GET /stream`) with a live/offline indicator.
- **Alerts** — decision-card queue from `GET /decision_cards` (audit) plus a live SSE feed; new cards prepend with a brief highlight, and cards with an override are tagged inline.
- **Alert detail** — tabs for:
  - **Overview**: event metadata + triage + explanation + effective action (respects overrides)
  - **Detector**: rule / federated / final score bars
  - **Policy**: rule id, permitted action, human-review flag
  - **OSINT**: verdict, providers, indicator count, short explanation
  - **LLM**: provenance (tier / provider / model), analyst summary, helpdesk explanation, next steps
  - **Federated**: FL score and model round
  - **History**: every override recorded for this card, with reviewer, reason, and timestamp
  - **Raw**: the full decision card JSON with copy-to-clipboard
  - Plus an **Override action** button that posts to `POST /log_override` and updates the view optimistically.
- **Traffic** — status, detectors and warmup state, anomaly table (EWMA z-score / rate-burst / isolation forest), a per-window volume chart, synthetic-traffic controls (start/stop/burst), and `POST /detect` trigger.
- **Federated ML** — round state from the aggregator (`/status`) and the global model (`/global_model`) with a per-feature weight chart.
- **Simulator** — list scenarios (`/scenarios`), run a scenario (`/run_scenario`) and watch per-event results.
- **Services** — health probes (`/health`) for every backend with latency.

All data comes from existing FastAPI services. No backend change is required.

## Run

### With docker-compose (recommended)

```bash
docker compose build console
docker compose up -d console
```

Open <http://localhost:8080>. The nginx in the container proxies `/api/<service>/*` to the other services on the Compose default bridge network.

### Local dev (hot-reload)

```bash
cd console
npm install
npm run dev
```

Open <http://localhost:5173>. Vite dev-server proxies `/api/*` to the published ports on `localhost` (8000–8028). Override any service URL with env vars, e.g.:

```bash
AUDIT_URL=http://localhost:8022 \
ORCHESTRATOR_URL=http://localhost:8021 \
npm run dev
```

## Design notes

- **Dark theme first.** Surface scale `#0b0f14 → #18212c`, accent cyan-400, severity palette deliberately distinct (info/low/medium/high/critical).
- **Inter** for UI, **JetBrains Mono** for IDs, hashes, JSON, scores.
- **Keyboard-ready** (search hint, copy buttons); no heavy runtime deps — just React, React-Router, Tailwind, lucide-react, clsx.
- **Everything is typed** against the real decision-card schema emitted by the orchestrator so the UI breaks loudly if the schema drifts.

## File map

```
console/
  package.json
  vite.config.ts        # /api/* dev proxy
  tailwind.config.ts    # tokens: surface scale, severity, accent
  nginx.conf            # prod proxy (same /api/* shape)
  Dockerfile            # node build -> nginx
  src/
    main.tsx
    App.tsx             # router
    index.css           # tokens + base components
    lib/
      api.ts            # typed fetch client
      format.ts         # severity, time, score helpers
      cn.ts             # clsx helper
    components/
      layout/Shell.tsx  # left nav + topbar + content
      ui/               # Card, Badge, Tabs, ScoreBar, JsonView
    pages/
      Dashboard.tsx   # stacked time-series (recharts) + SSE live updates
      Alerts.tsx      # SSE prepend, highlight, override badges
      AlertDetail.tsx # tabs + override modal + history
      Traffic.tsx     # anomaly table + synthetic controls + volume chart
      Simulator.tsx
      Federated.tsx
      Services.tsx
      Settings.tsx
```

## Real-time updates

The audit service (`audit/app.py`) exposes `GET /stream` as a text/event-stream. It emits two event types:

- `event: decision` — fired on every `POST /log_decision` with the decision card.
- `event: override` — fired on every `POST /log_override` with the override record.

Heartbeats are sent every 15 s so proxies don't time out. nginx has a dedicated location block (`location = /api/audit/stream`) with `proxy_buffering off` so the stream reaches the browser unbuffered.

On the client, `src/lib/sse.ts` is a thin typed EventSource wrapper. Dashboard and Alerts subscribe on mount; browsers reconnect automatically if the server restarts.
