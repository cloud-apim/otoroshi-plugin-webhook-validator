# Cloud APIM – YouSign Webhook Validator – Otoroshi plugin

An [Otoroshi](https://github.com/MAIF/otoroshi) plugin that validates [YouSign](https://developers.yousign.com/docs/use-webhooks-in-your-app) webhook payloads before they reach your backend.

## How it works

The plugin is provider-agnostic: the signature header, HMAC algorithm and prefix are all configurable. Out of the box it is pre-configured for YouSign, whose webhooks include an `X-Yousign-Signature-256` header containing an HMAC-SHA256 hash of the raw request body prefixed with `sha256=`.

The plugin:

1. Reads the raw request body.
2. Computes `HMAC-<algorithm>(secret, rawBody)` using the configured secret and algorithm.
3. Prepends the configured prefix to the hex-encoded hash to form the expected signature.
4. Compares the result (constant-time, to prevent timing attacks) against the configured signature header.
5. Forwards the request to your backend unchanged when the signature is valid.
6. Returns **401 Unauthorized** when the signature is missing or invalid.

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
        "plugin": "cp:otoroshi_plugins.com.cloud.apim.otoroshi.plugins.yousign.YouSignWebhookValidator",
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

## Plugin configuration

| Field              | Type     | Required | Default                    | Description                                                                          |
|--------------------|----------|----------|----------------------------|--------------------------------------------------------------------------------------|
| `secret`           | `string` | yes      | –                          | The HMAC secret shared with the webhook provider (e.g. YouSign webhook secret).      |
| `signature_header` | `string` | no       | `X-Yousign-Signature-256`  | Name of the HTTP header that carries the signature.                                  |
| `algorithm`        | `string` | no       | `HmacSHA256`               | Java HMAC algorithm name. Supported values: `HmacSHA256`, `HmacSHA512`, `HmacSHA384`, `HmacSHA1`. |
| `prefix`           | `string` | no       | derived from `algorithm`   | String prepended to the hex hash before comparison (e.g. `sha256=`). Defaults are derived automatically from the chosen algorithm. |

```json
{
  "secret": "your-webhook-secret",
  "signature_header": "X-Yousign-Signature-256",
  "algorithm": "HmacSHA256",
  "prefix": "sha256="
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

| Status | Body | Meaning |
|--------|------|---------|
| forwarded to backend | – | Signature is valid, request is passed through unchanged. |
| `401 Unauthorized` | `{ "error": "missing X-Yousign-Signature-256 header" }` | The header was not present in the incoming request. |
| `401 Unauthorized` | `{ "error": "invalid signature" }` | The computed HMAC does not match the header value. |
| `401 Unauthorized` | `{ "error": "webhook secret not configured" }` | The plugin `secret` field is empty. |

## YouSign webhook headers

The following headers are sent by YouSign on every webhook call:

| Header | Description |
|--------|-------------|
| `X-Yousign-Signature-256` | `sha256=<hmac-sha256 hex>` – used by this plugin for payload authentication |
| `X-Yousign-Retry` | Retry attempt counter (0 for the first delivery) |
| `X-Yousign-Issued-At` | Timestamp of webhook transmission |
| `Content-Type` | Always `application/json` |
| `User-Agent` | Always `Yousign Webhook Bot` |

## Security notes

- The plugin uses **constant-time byte comparison** (`MessageDigest.isEqual`) to prevent timing-based side-channel attacks.
- YouSign only delivers webhooks over **HTTPS**; make sure your Otoroshi route is exposed on a TLS-enabled domain.
- YouSign webhooks originate from the following CIDRs: `5.39.7.128/28`, `52.143.162.31`, `51.103.81.166`. You can add an Otoroshi IP allowlist plugin alongside this one for defence-in-depth.

## Build

```shell
sbt assembly
```

The resulting jar is placed in `target/scala-2.12/otoroshi-plugin-yousign-webhook-validator-assembly_2.12-dev.jar`.

Copy it to your Otoroshi `plugins/` directory (or reference it via the classpath loader) and restart Otoroshi.
