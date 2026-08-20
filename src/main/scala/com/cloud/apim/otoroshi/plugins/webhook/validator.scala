package otoroshi_plugins.com.cloud.apim.otoroshi.plugins.webhook

import org.apache.pekko.stream.Materializer
import org.apache.pekko.stream.scaladsl.Source
import org.apache.pekko.util.ByteString
import otoroshi.env.Env
import otoroshi.next.plugins.api.*
import otoroshi.utils.syntax.implicits.*
import play.api.Logger
import play.api.libs.json.*
import play.api.mvc.{Result, Results}

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Failure, Success, Try}

extension (bytes: Array[Byte]) {
  private def hex: String = bytes.map(b => f"${b & 0xff}%02x").mkString
}

extension (self: String) {
  // constant-time comparison to prevent timing-attack side channels
  private def constantTimeEquals(other: String): Boolean =
    MessageDigest.isEqual(self.getBytes(StandardCharsets.UTF_8), other.getBytes(StandardCharsets.UTF_8))
}

case class WebhookValidatorConfig(
  secret: String                   = "",
  signatureHeader: String          = "X-Hub-Signature-256",
  algorithm: String                = "HmacSHA256",
  prefix: String                   = "sha256=",
  signingPayloadTemplate: String   = "{body}",
  timestampHeader: String          = "",
  timestampExtractionRegex: String = "",
  signatureExtractionRegex: String = "",
) extends NgPluginConfig {
  def json: JsValue = WebhookValidatorConfig.format.writes(this)
}

object WebhookValidatorConfig {
  val default: WebhookValidatorConfig = WebhookValidatorConfig()
  given format: Format[WebhookValidatorConfig] = new Format[WebhookValidatorConfig] {
    override def writes(o: WebhookValidatorConfig): JsValue = Json.obj(
      "secret"                    -> o.secret,
      "signature_header"          -> o.signatureHeader,
      "algorithm"                 -> o.algorithm,
      "prefix"                    -> o.prefix,
      "signing_payload_template"  -> o.signingPayloadTemplate,
      "timestamp_header"          -> o.timestampHeader,
      "timestamp_extraction_regex"-> o.timestampExtractionRegex,
      "signature_extraction_regex"-> o.signatureExtractionRegex,
    )
    override def reads(json: JsValue): JsResult[WebhookValidatorConfig] = Try {
      val algo = json.select("algorithm").asOpt[String].getOrElse("HmacSHA256")
      WebhookValidatorConfig(
        secret                   = json.select("secret").asOpt[String].getOrElse(""),
        signatureHeader          = json.select("signature_header").asOpt[String].getOrElse("X-Hub-Signature-256"),
        algorithm                = algo,
        prefix                   = json.select("prefix").asOpt[String].getOrElse(WebhookValidatorConfig.defaultPrefix(algo)),
        signingPayloadTemplate   = json.select("signing_payload_template").asOpt[String].getOrElse("{body}"),
        timestampHeader          = json.select("timestamp_header").asOpt[String].getOrElse(""),
        timestampExtractionRegex = json.select("timestamp_extraction_regex").asOpt[String].getOrElse(""),
        signatureExtractionRegex = json.select("signature_extraction_regex").asOpt[String].getOrElse(""),
      )
    } match {
      case Failure(e) => JsError(e.getMessage)
      case Success(e) => JsSuccess(e)
    }
  }

  def defaultPrefix(algorithm: String): String = algorithm.toLowerCase match {
    case a if a.contains("sha512") => "sha512="
    case a if a.contains("sha384") => "sha384="
    case a if a.contains("sha256") => "sha256="
    case a if a.contains("sha1")   => "sha1="
    case a if a.contains("md5")    => "md5="
    case _                         => "sha256="
  }

  val configFlow: Seq[String] = Seq(
    "secret", "signature_header", "algorithm", "prefix",
    "signing_payload_template", "timestamp_header",
    "timestamp_extraction_regex", "signature_extraction_regex",
  )
  val configSchema: Option[JsObject] = Some(Json.obj(
    "secret"           -> Json.obj("type" -> "password", "label" -> "Webhook Secret"),
    "signature_header" -> Json.obj("type" -> "string",   "label" -> "Signature Header"),
    "algorithm"        -> Json.obj(
      "type"   -> "select",
      "label"  -> "HMAC Algorithm",
      "props"  -> Json.obj(
        "options" -> Json.arr(
          Json.obj("label" -> "HMAC-SHA256", "value" -> "HmacSHA256"),
          Json.obj("label" -> "HMAC-SHA512", "value" -> "HmacSHA512"),
          Json.obj("label" -> "HMAC-SHA384", "value" -> "HmacSHA384"),
          Json.obj("label" -> "HMAC-SHA1",   "value" -> "HmacSHA1"),
        ),
      ),
    ),
    "prefix"                     -> Json.obj("type" -> "string", "label" -> "Signature Prefix"),
    "signing_payload_template"   -> Json.obj("type" -> "string", "label" -> "Signing Payload Template (use {body} and {timestamp})"),
    "timestamp_header"           -> Json.obj("type" -> "string", "label" -> "Timestamp Header (e.g. X-Slack-Request-Timestamp)"),
    "timestamp_extraction_regex" -> Json.obj("type" -> "string", "label" -> "Regex to extract timestamp from signature header (e.g. t=([^,]+))"),
    "signature_extraction_regex" -> Json.obj("type" -> "string", "label" -> "Regex to extract signature from signature header (e.g. v1=([^,]+))"),
  ))
}

class WebhookPayloadValidator extends NgRequestTransformer {

  private val logger = Logger("otoroshi-cloud-apim-webhook-payload-validator")

  override def steps: Seq[NgStep]                          = Seq(NgStep.TransformRequest)
  override def categories: Seq[NgPluginCategory]           = Seq(NgPluginCategory.AccessControl, NgPluginCategory.Custom("Cloud APIM"))
  override def visibility: NgPluginVisibility              = NgPluginVisibility.NgUserLand
  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = false
  override def name: String                                = "Cloud APIM - Webhook Payload Validator"
  override def description: Option[String]                 = Some("This plugin validates webhook payloads by verifying an HMAC signature. The header name, algorithm, prefix and signing payload template are all configurable.")
  override def defaultConfigObject: Option[NgPluginConfig] = Some(WebhookValidatorConfig.default)
  override def noJsForm: Boolean                           = true
  override def configFlow: Seq[String]                     = WebhookValidatorConfig.configFlow
  override def configSchema: Option[JsObject]              = WebhookValidatorConfig.configSchema

  override def isTransformRequestAsync: Boolean            = true
  override def usesCallbacks: Boolean                      = false
  override def transformsRequest: Boolean                  = true
  override def transformsResponse: Boolean                 = false
  override def transformsError: Boolean                    = false

  override def start(env: Env): Future[Unit] = {
    env.logger.info("[Cloud APIM] the 'Webhook Validator' plugin is available !")
    ().vfuture
  }

  private def computeHmac(algorithm: String, secret: String, body: ByteString): String = {
    val mac     = Mac.getInstance(algorithm)
    val keySpec = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), algorithm)
    mac.init(keySpec)
    mac.doFinal(body.toArray).hex
  }

  private def buildSigningPayload(template: String, bodyBytes: ByteString, timestamp: String): ByteString = {
    if (template.isEmpty || template == "{body}") {
      bodyBytes
    } else {
      ByteString(template.replace("{timestamp}", timestamp).replace("{body}", bodyBytes.utf8String), "UTF-8")
    }
  }

  override def transformRequest(ctx: NgTransformerRequestContext)(using env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[Result, NgPluginHttpRequest]] = {
    val config = ctx.cachedConfig(internalName)(WebhookValidatorConfig.format).getOrElse(WebhookValidatorConfig.default)
    if (config.secret.isEmpty) {
      logger.warn("[Webhook Validator] no secret configured, rejecting request")
      Left(Results.Unauthorized(Json.obj("error" -> "webhook secret not configured"))).vfuture
    } else {
      ctx.request.headers.get(config.signatureHeader) match {
        case None =>
          if (logger.isDebugEnabled) logger.debug(s"[Webhook Validator] missing ${config.signatureHeader} header")
          Left(Results.Unauthorized(Json.obj("error" -> s"missing ${config.signatureHeader} header"))).vfuture
        case Some(rawSignatureHeader) =>
          // Extract actual signature value from the header (e.g. Stripe: "t=...,v1=<sig>")
          val receivedSignature: String =
            if (config.signatureExtractionRegex.nonEmpty)
              config.signatureExtractionRegex.r.findFirstMatchIn(rawSignatureHeader).map(_.group(1)).getOrElse(rawSignatureHeader)
            else
              rawSignatureHeader

          // Resolve timestamp when the template needs it
          val needsTimestamp = config.signingPayloadTemplate.contains("{timestamp}")
          val timestampOpt: Option[String] =
            if (!needsTimestamp) Some("")
            else if (config.timestampHeader.nonEmpty)
              ctx.request.headers.get(config.timestampHeader)
            else if (config.timestampExtractionRegex.nonEmpty)
              config.timestampExtractionRegex.r.findFirstMatchIn(rawSignatureHeader).map(_.group(1))
            else Some("")

          timestampOpt match {
            case None =>
              val source = if (config.timestampHeader.nonEmpty) s"header '${config.timestampHeader}'" else s"signature header via regex '${config.timestampExtractionRegex}'"
              if (logger.isDebugEnabled) logger.debug(s"[Webhook Validator] missing timestamp from $source")
              Left(Results.Unauthorized(Json.obj("error" -> s"missing timestamp"))).vfuture
            case Some(timestamp) =>
              ctx.otoroshiRequest.body.runFold(ByteString.empty)(_ ++ _).map { bodyBytes =>
                val signingPayload    = buildSigningPayload(config.signingPayloadTemplate, bodyBytes, timestamp)
                val computedHash      = computeHmac(config.algorithm, config.secret, signingPayload)
                val expectedSignature = s"${config.prefix}$computedHash"

                if (logger.isDebugEnabled) {
                  logger.debug(s"[Webhook Validator] expected : $expectedSignature")
                  logger.debug(s"[Webhook Validator] received : $receivedSignature")
                }

                if (expectedSignature.constantTimeEquals(receivedSignature)) {
                  // Re-emit the already-consumed body so downstream plugins / the backend still see it
                  Right(ctx.otoroshiRequest.copy(body = Source.single(bodyBytes)))
                } else {
                  logger.warn(s"[Webhook Validator] invalid signature for header ${config.signatureHeader}")
                  Left(Results.Unauthorized(Json.obj("error" -> "invalid signature")))
                }
              }
          }
      }
    }
  }
}
