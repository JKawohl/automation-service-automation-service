# Automation Service (Portable n8n Alternative)

`automation-service` is a small config-as-code automation plane for the homelab/appliance.
It is intended to replace `n8n` for core security/compliance workflows where portability,
versioning, and testability matter.

## V1 goals

- Generic event ingest (`POST /v1/events`)
- Wazuh adapter endpoint (`POST /v1/events/wazuh`)
- JSON rules engine (config-as-code)
- SQLite idempotency + audit trail
- Connector actions:
  - `log`
  - `http_request`
  - `glpi_pam_request` (uses `glpi/scripts/pam_privileged_access_request.py`)

## Why this instead of n8n

- No UI-exported workflow drift
- Easier to ship per-customer (Hetzner/on-prem) with `docker compose`
- Rule packs live in git (`automation-service/config/rules.json`)
- Easier CI validation and deterministic behavior

## Service endpoints

- `GET /healthz` – health + rule count
- `GET /v1/rules` – loaded rule pack (requires bearer token if configured)
- `GET /v1/events/<event_id>` – stored event + action audit (requires bearer token if configured)
- `POST /v1/events` – generic event ingest
- `POST /v1/events/wazuh` – Wazuh alert JSON adapter

## Event schema (generic)

Example:

```json
{
  "source": "pam-portal",
  "event_type": "pam.access_request.open",
  "event_time": "2026-02-26T13:30:00Z",
  "severity": 5,
  "external_ref": "req-123",
  "actor": {"id": "john"},
  "target": {"id": "winlab-srv25", "protocol": "rdp"},
  "labels": ["pam", "request"],
  "metadata": {"duration": "30m", "reason": "Patching"},
  "payload": {"raw": "optional"}
}
```

## Rules

- Copy `automation-service/config/rules.example.json` to `automation-service/config/rules.json`
- Or use the included PAM-focused starter pack: `automation-service/config/rules.pam-v1.json`
- Rules are evaluated in order
- Matching supports `equals`, `any_equals`, `contains`, `all_contains`, `min_severity`
- Actions are executed in order for each matched rule

Suggested start:

```bash
cp automation-service/config/rules.pam-v1.json automation-service/config/rules.json
```

## Deploy (OpenBao-compatible)

This service follows the existing `compose-with-openbao.sh` pattern.
Store secrets/env in OpenBao at `secret/services/automation-service`.

Suggested keys:

- `AUTOMATION_WEBHOOK_BEARER_TOKEN`
- `AUTOMATION_ACTION_MODE` (`dry-run` or `live`)
- `AUTOMATION_EVENT_RETENTION_DAYS`

Optional (if using GLPI connector action):

- `GLPI_API_URL`
- `GLPI_API_APP_TOKEN`
- `GLPI_API_USER_TOKEN`
- `GLPI_API_VERIFY_SSL`
- `GLPI_TICKET_REQUESTER_ID`
- `GLPI_PAM_ACCESS_CATEGORY_ID`
- `GLPI_PAM_CLOSE_STATUS`

Bootstrap helper (stores defaults + webhook token in OpenBao):

```bash
./scripts/openbao-configure-automation-service.sh --print-token
```

Non-secret root `.env` values:

- `AUTOMATION_SERVICE_DOMAIN=automation.<your-domain>`

Start:

```bash
cp automation-service/config/rules.pam-v1.json automation-service/config/rules.json
./scripts/compose-with-openbao.sh automation-service -d
```

## Test

Health:

```bash
curl -fsS https://automation.<your-domain>/healthz
```

Generic event (bearer token optional if unset):

```bash
curl -fsS -X POST https://automation.<your-domain>/v1/events \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{
    "source":"pam-portal",
    "event_type":"pam.access_request.open",
    "external_ref":"req-123",
    "actor":{"id":"john"},
    "target":{"id":"winlab-srv25","protocol":"rdp"},
    "metadata":{"duration":"30m","reason":"Patching"}
  }'
```

Wazuh adapter event:

```bash
curl -fsS -X POST https://automation.<your-domain>/v1/events/wazuh \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d @sample-wazuh-alert.json
```

Included test payloads:

- `automation-service/examples/wazuh-guacamole-auth-failed.json`
- `automation-service/examples/wazuh-guacamole-admin-change.json`
- `automation-service/examples/event-pam-access-open.json`
- `automation-service/examples/event-pam-access-close.json`

Examples:

```bash
curl -fsS -X POST https://automation.<your-domain>/v1/events/wazuh \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d @automation-service/examples/wazuh-guacamole-auth-failed.json
```

```bash
curl -fsS -X POST https://automation.<your-domain>/v1/events \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d @automation-service/examples/event-pam-access-open.json
```

## Packaging notes

- `rules.json` is the customer-specific policy pack
- SQLite is fine for single-customer V1 appliance deployments
- For MSP/multi-tenant, migrate to Postgres and add tenant scoping later
- `n8n` can remain optional for ad-hoc workflows, not a core dependency
