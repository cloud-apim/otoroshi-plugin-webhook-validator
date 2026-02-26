package otoroshi_plugins.com.cloud.apim.otoroshi.plugins.webhook

import akka.stream.Materializer
import akka.stream.scaladsl.Source
import akka.util.ByteString
import otoroshi.env.Env
import otoroshi.next.plugins.api._
import otoroshi.next.proxy.NgProxyEngineError
import otoroshi.utils.syntax.implicits._
import play.api.Logger
import play.api.libs.json._
import play.api.mvc.{Result, Results}

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Failure, Success, Try}

case class WebhookValidatorConfig(
  secret: String          = "",
  signatureHeader: String = "X-Yousign-Signature-256",
  algorithm: String       = "HmacSHA256",
  prefix: String          = "sha256=",
) extends NgPluginConfig {
  def json: JsValue = WebhookValidatorConfig.format.writes(this)
}

object WebhookValidatorConfig {
  val default: WebhookValidatorConfig = WebhookValidatorConfig()
  val format: Format[WebhookValidatorConfig] = new Format[WebhookValidatorConfig] {
    override def writes(o: WebhookValidatorConfig): JsValue = Json.obj(
      "secret"           -> o.secret,
      "signature_header" -> o.signatureHeader,
      "algorithm"        -> o.algorithm,
      "prefix"           -> o.prefix,
    )
    override def reads(json: JsValue): JsResult[WebhookValidatorConfig] = Try {
      val algo = json.select("algorithm").asOpt[String].getOrElse("HmacSHA256")
      WebhookValidatorConfig(
        secret          = json.select("secret").asOpt[String].getOrElse(""),
        signatureHeader = json.select("signature_header").asOpt[String].getOrElse("X-Yousign-Signature-256"),
        algorithm       = algo,
        prefix          = json.select("prefix").asOpt[String].getOrElse(WebhookValidatorConfig.defaultPrefix(algo)),
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

  val configFlow: Seq[String] = Seq("secret", "signature_header", "algorithm", "prefix")
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
    "prefix"           -> Json.obj("type" -> "string", "label" -> "Signature Prefix"),
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
  override def description: Option[String]                 = Some("This plugin validates webhook payloads by verifying an HMAC signature. The header name, algorithm and prefix are all configurable.")
  override def defaultConfigObject: Option[NgPluginConfig] = Some(WebhookValidatorConfig.default)
  override def noJsForm: Boolean                           = false
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
    val keySpec = new SecretKeySpec(secret.getBytes("UTF-8"), algorithm)
    mac.init(keySpec)
    mac.doFinal(body.toArray).map(b => f"${b & 0xff}%02x").mkString
  }

  override def transformRequest(ctx: NgTransformerRequestContext)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[Result, NgPluginHttpRequest]] = {
    val config = ctx.cachedConfig(internalName)(WebhookValidatorConfig.format).getOrElse(WebhookValidatorConfig.default)
    if (config.secret.isEmpty) {
      logger.warn("[Webhook Validator] no secret configured, rejecting request")
      Left(Results.Unauthorized(Json.obj("error" -> "webhook secret not configured"))).vfuture
    } else {
      ctx.request.headers.get(config.signatureHeader) match {
        case None =>
          if (logger.isDebugEnabled) logger.debug(s"[Webhook Validator] missing ${config.signatureHeader} header")
          Left(Results.Unauthorized(Json.obj("error" -> s"missing ${config.signatureHeader} header"))).vfuture
        case Some(receivedSignature) =>
          ctx.otoroshiRequest.body.runFold(ByteString.empty)(_ ++ _).map { bodyBytes =>
            val computedHash      = computeHmac(config.algorithm, config.secret, bodyBytes)
            val expectedSignature = s"${config.prefix}$computedHash"

            if (logger.isDebugEnabled) {
              logger.debug(s"[Webhook Validator] expected : $expectedSignature")
              logger.debug(s"[Webhook Validator] received : $receivedSignature")
            }
            // Constant-time comparison to prevent timing-attack side channels
            val expected = expectedSignature.getBytes("UTF-8")
            val received = receivedSignature.getBytes("UTF-8")

            if (MessageDigest.isEqual(expected, received)) {
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
