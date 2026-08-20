# Cloud APIM – Webhook Validator – Otoroshi plugin

An [Otoroshi](https://github.com/MAIF/otoroshi) plugin that validates webhook payloads before they reach your backend using body payload signature validation.

## How it works

The plugin is provider-agnostic: the signature header, HMAC algorithm, prefix and signing payload template are all configurable.

The plugin:

1. Reads the raw request body.
2. Optionally resolves a timestamp (from a dedicated header or extracted from the signature header via regex).
3. Builds the signing payload by applying the `signing_payload_template` (e.g. `{timestamp}.{body}` for Stripe, `v0:{timestamp}:{body}` for Slack, or plain `{body}` for most providers).
4. Computes `HMAC-<algorithm>(secret, signingPayload)` using the configured secret and algorithm.
5. Prepends the configured prefix to the hex-encoded hash to form the expected signature.
6. Optionally extracts the actual signature from the header value using a regex (e.g. `v1=([^,]+)` for Stripe).
7. Compares the result (constant-time, to prevent timing attacks) against the extracted or raw signature header value.
8. Forwards the request to your backend unchanged when the signature is valid.
9. Returns **401 Unauthorized** when the signature is missing, the timestamp cannot be resolved, or the signature is invalid.

## Create a route to receive GitHub webhooks

```shell
$ curl -X POST 'http://otoroshi-api.oto.tools:8080/api/routes' \
  -H "Content-type: application/json" \
  -u 'admin-api-apikey-id:admin-api-apikey-secret' \
  -d '{
    "name": "github-webhook-receiver",
    "frontend": {
      "domains": ["webhooks.oto.tools/github"]
    },
    "backend": {
      "targets": [{
        "hostname": "my-backend.example.com",
        "port": 443,
        "tls": true
      }]
    },
    "plugins": [
      {
        "enabled": true,
        "plugin": "cp:otoroshi_plugins.com.cloud.apim.otoroshi.plugins.webhook.WebhookPayloadValidator",
        "config": {
          "secret": "your-github-webhook-secret",
          "signature_header": "X-Hub-Signature-256",
          "algorithm": "HmacSHA256",
          "prefix": "sha256="
        }
      }
    ]
  }'
```

## Create a route to receive YouSign webhooks

```shell
$ curl -X POST 'http://otoroshi-api.oto.tools:8080/api/routes' \
  -H "Content-type: application/json" \
  -u 'admin-api-apikey-id:admin-api-apikey-secret' \
  -d '{
    "name": "yousign-webhook-receiver",
    "frontend": {
      "domains": ["webhooks.oto.tools/yousign"]
    },
    "backend": {
      "targets": [{
        "hostname": "my-backend.example.com",
        "port": 443,
        "tls": true
      }]
    },
    "plugins": [
      {
        "enabled": true,
        "plugin": "cp:otoroshi_plugins.com.cloud.apim.otoroshi.plugins.webhook.WebhookPayloadValidator",
        "config": {
          "secret": "your-yousign-webhook-secret",
          "signature_header": "X-Yousign-Signature-256",
          "algorithm": "HmacSHA256",
          "prefix": "sha256="
        }
      }
    ]
  }'
```

## Create a route to receive Stripe webhooks

Stripe signs the payload as `{timestamp}.{body}` and sends the signature as `t=<timestamp>,v1=<sig>` in the `Stripe-Signature` header. Both the timestamp and the signature must be extracted from that header with a regex.

```shell
$ curl -X POST 'http://otoroshi-api.oto.tools:8080/api/routes' \
  -H "Content-type: application/json" \
  -u 'admin-api-apikey-id:admin-api-apikey-secret' \
  -d '{
    "name": "stripe-webhook-receiver",
    "frontend": {
      "domains": ["webhooks.oto.tools/stripe"]
    },
    "backend": {
      "targets": [{
        "hostname": "my-backend.example.com",
        "port": 443,
        "tls": true
      }]
    },
    "plugins": [
      {
        "enabled": true,
        "plugin": "cp:otoroshi_plugins.com.cloud.apim.otoroshi.plugins.webhook.WebhookPayloadValidator",
        "config": {
          "secret": "whsec_your-stripe-webhook-secret",
          "signature_header": "Stripe-Signature",
          "algorithm": "HmacSHA256",
          "prefix": "",
          "signing_payload_template": "{timestamp}.{body}",
          "timestamp_extraction_regex": "t=([^,]+)",
          "signature_extraction_regex": "v1=([^,]+)"
        }
      }
    ]
  }'
```

## Create a route to receive Slack webhooks

Slack signs the payload as `v0:{timestamp}:{body}` and sends the timestamp in a separate `X-Slack-Request-Timestamp` header. The signature header value is `v0=<sig>`.

```shell
$ curl -X POST 'http://otoroshi-api.oto.tools:8080/api/routes' \
  -H "Content-type: application/json" \
  -u 'admin-api-apikey-id:admin-api-apikey-secret' \
  -d '{
    "name": "slack-webhook-receiver",
    "frontend": {
      "domains": ["webhooks.oto.tools/slack"]
    },
    "backend": {
      "targets": [{
        "hostname": "my-backend.example.com",
        "port": 443,
        "tls": true
      }]
    },
    "plugins": [
      {
        "enabled": true,
        "plugin": "cp:otoroshi_plugins.com.cloud.apim.otoroshi.plugins.webhook.WebhookPayloadValidator",
        "config": {
          "secret": "your-slack-signing-secret",
          "signature_header": "X-Slack-Signature",
          "algorithm": "HmacSHA256",
          "prefix": "v0=",
          "signing_payload_template": "v0:{timestamp}:{body}",
          "timestamp_header": "X-Slack-Request-Timestamp"
        }
      }
    ]
  }'
```

## Plugin configuration

| Field                        | Type     | Required | Default                  | Description                                                                                                                          |
|------------------------------|----------|----------|--------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| `secret`                     | `string` | yes      | –                        | The HMAC secret shared with the webhook provider.                                                                                    |
| `signature_header`           | `string` | no       | `X-Hub-Signature-256`    | Name of the HTTP header that carries the signature.                                                                                  |
| `algorithm`                  | `string` | no       | `HmacSHA256`             | Java HMAC algorithm name. Supported values: `HmacSHA256`, `HmacSHA512`, `HmacSHA384`, `HmacSHA1`.                                   |
| `prefix`                     | `string` | no       | derived from `algorithm` | String prepended to the hex hash before comparison (e.g. `sha256=`). Use `""` when the comparison value is raw hex (Stripe).         |
| `signing_payload_template`   | `string` | no       | `{body}`                 | Template for the HMAC input. Supports `{body}` (raw body) and `{timestamp}`. Examples: `{timestamp}.{body}` (Stripe), `v0:{timestamp}:{body}` (Slack). |
| `timestamp_header`           | `string` | no       | `""`                     | Name of a separate HTTP header containing the timestamp (e.g. `X-Slack-Request-Timestamp` for Slack).                               |
| `timestamp_extraction_regex` | `string` | no       | `""`                     | Regex with one capture group to extract the timestamp from the **signature header** value (e.g. `t=([^,]+)` for Stripe).             |
| `signature_extraction_regex` | `string` | no       | `""`                     | Regex with one capture group to extract the actual signature from the **signature header** value (e.g. `v1=([^,]+)` for Stripe). When empty the full header value is used. |

```json
{
  "secret": "your-webhook-secret",
  "signature_header": "X-Hub-Signature-256",
  "algorithm": "HmacSHA256",
  "prefix": "sha256=",
  "signing_payload_template": "{body}",
  "timestamp_header": "",
  "timestamp_extraction_regex": "",
  "signature_extraction_regex": ""
}
```

### Algorithm / prefix defaults

| `algorithm`  | Default `prefix` |
|--------------|-----------------|
| `HmacSHA256` | `sha256=`       |
| `HmacSHA512` | `sha512=`       |
| `HmacSHA384` | `sha384=`       |
| `HmacSHA1`   | `sha1=`         |

## Responses

| Status | Body                                           | Meaning |
|--------|------------------------------------------------|---------|
| forwarded to backend | –                                              | Signature is valid, request is passed through unchanged. |
| `401 Unauthorized` | `{ "error": "missing xxxx header" }`           | The signature header was not present in the incoming request. |
| `401 Unauthorized` | `{ "error": "missing timestamp" }`             | The timestamp could not be resolved (missing header or regex did not match). |
| `401 Unauthorized` | `{ "error": "invalid signature" }`             | The computed HMAC does not match the header value. |
| `401 Unauthorized` | `{ "error": "webhook secret not configured" }` | The plugin `secret` field is empty. |


## Security notes

- The plugin uses **constant-time byte comparison** (`MessageDigest.isEqual`) to prevent timing-based side-channel attacks.

## Build

```shell
sbt assembly
```

The resulting jar is placed in `target/scala-3.8.4/otoroshi-plugin-webhook-validator-assembly_3-dev.jar`.

Copy it to your Otoroshi `plugins/` directory (or reference it via the classpath loader) and restart Otoroshi.
