# The appliance ConfigMap

On the Sneakers appliance, the platform controller publishes the `sneakers-appliance` ConfigMap in
the install's namespace, and only it writes to it. The gateway reads it with one `get` every
`APPLIANCE_POLL_INTERVAL` (10 seconds by default), using its own ServiceAccount token, and keeps
the latest copy. There is no other edge: the gateway never calls the appliance.

On a plain Kubernetes install the ConfigMap doesn't exist, so the data is empty and nothing
changes. When the API server can't be reached or refuses the read, the gateway keeps the last data
it read, so a short API outage doesn't drop it out of maintenance. Each change of outcome (found,
absent, forbidden, error) is logged once.

## Keys the gateway reads

| Key | Values | Effect |
|---|---|---|
| `maintenance` | `on`, anything else is off | `on` puts the gateway in read-only maintenance (see [api.md](api.md), "Maintenance"). `MAINTENANCE_READONLY` turns it on as well, whatever the ConfigMap says. |
| `maintenanceReason` | free text | Shown as the `maintenance` query's `reason` while it's on. |
| `sessionsEndedAt` | an RFC 3339 time | Every session issued before it is ended: the next request with it gets the signed-out answer and the session is deleted, on every replica and after a restart. Sessions issued later work, so people can sign in again. The appliance sets it when it enters maintenance. A value that isn't a time is ignored. |

## Access

The gateway's ServiceAccount needs a Role with `get` on `configmaps` limited to
`resourceNames: [sneakers-appliance]`, and the pod needs the ServiceAccount token, CA and
namespace mounted at `/var/run/secrets/kubernetes.io/serviceaccount/` (or the token at
`APPLIANCE_TOKEN_FILE`). Grant both in the chart that installs the gateway.
