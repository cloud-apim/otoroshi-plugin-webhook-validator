package otoroshi_plugins.com.cloud.apim.otoroshi.plugins.yousign

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

case class YouSignWebhookValidatorConfig(
  secret: String = "",
) extends NgPluginConfig {
  def json: JsValue = YouSignWebhookValidatorConfig.format.writes(this)
}

object YouSignWebhookValidatorConfig {
  val default: YouSignWebhookValidatorConfig = YouSignWebhookValidatorConfig()
  val format: Format[YouSignWebhookValidatorConfig] = new Format[YouSignWebhookValidatorConfig] {
    override def writes(o: YouSignWebhookValidatorConfig): JsValue = Json.obj(
      "secret" -> o.secret,
    )
    override def reads(json: JsValue): JsResult[YouSignWebhookValidatorConfig] = Try {
      YouSignWebhookValidatorConfig(
        secret = json.select("secret").asOpt[String].getOrElse(""),
      )
    } match {
      case Failure(e) => JsError(e.getMessage)
      case Success(e) => JsSuccess(e)
    }
  }
  val configFlow: Seq[String] = Seq("secret")
  val configSchema: Option[JsObject] = Some(Json.obj(
    "secret" -> Json.obj("type" -> "password", "label" -> "Webhook Secret"),
  ))
}

class YouSignWebhookValidator extends NgRequestTransformer {

  private val logger = Logger("otoroshi-cloud-apim-yousign-webhook-validator")

  override def steps: Seq[NgStep]                          = Seq(NgStep.TransformRequest)
  override def categories: Seq[NgPluginCategory]           = Seq(NgPluginCategory.AccessControl, NgPluginCategory.Custom("Cloud APIM"))
  override def visibility: NgPluginVisibility              = NgPluginVisibility.NgUserLand
  override def multiInstance: Boolean                      = true
  override def core: Boolean                               = false
  override def name: String                                = "Cloud APIM - YouSign Webhook Validator"
  override def description: Option[String]                 = Some("This plugin validates YouSign webhook payloads by verifying the HMAC SHA-256 signature present in the X-Yousign-Signature-256 header.")
  override def defaultConfigObject: Option[NgPluginConfig] = Some(YouSignWebhookValidatorConfig.default)
  override def noJsForm: Boolean                           = false
  override def configFlow: Seq[String]                     = YouSignWebhookValidatorConfig.configFlow
  override def configSchema: Option[JsObject]              = YouSignWebhookValidatorConfig.configSchema

  override def isTransformRequestAsync: Boolean            = true
  override def usesCallbacks: Boolean                      = false
  override def transformsRequest: Boolean                  = true
  override def transformsResponse: Boolean                 = false
  override def transformsError: Boolean                    = false

  override def start(env: Env): Future[Unit] = {
    env.logger.info("[Cloud APIM] the 'YouSign Webhook Validator' plugin is available !")
    ().vfuture
  }

  private def computeHmacSha256(secret: String, body: ByteString): String = {
    val mac    = Mac.getInstance("HmacSHA256")
    val keySpec = new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256")
    mac.init(keySpec)
    mac.doFinal(body.toArray).map(b => f"${b & 0xff}%02x").mkString
  }

  override def transformRequest(ctx: NgTransformerRequestContext)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[Result, NgPluginHttpRequest]] = {
    val config = ctx.cachedConfig(internalName)(YouSignWebhookValidatorConfig.format).getOrElse(YouSignWebhookValidatorConfig.default)

    if (config.secret.isEmpty) {
      logger.warn("[YouSign Webhook Validator] no secret configured, rejecting request")
      Left(Results.Unauthorized(Json.obj("error" -> "webhook secret not configured"))).vfuture
    } else {
      ctx.request.headers.get("X-Yousign-Signature-256") match {
        case None =>
          if (logger.isDebugEnabled) logger.debug("[YouSign Webhook Validator] missing X-Yousign-Signature-256 header")
          Left(Results.Unauthorized(Json.obj("error" -> "missing X-Yousign-Signature-256 header"))).vfuture

        case Some(receivedSignature) =>
          ctx.otoroshiRequest.body.runFold(ByteString.empty)(_ ++ _).map { bodyBytes =>
            val computedHash      = computeHmacSha256(config.secret, bodyBytes)
            val expectedSignature = s"sha256=$computedHash"

            if (logger.isDebugEnabled) {
              logger.debug(s"[YouSign Webhook Validator] expected : $expectedSignature")
              logger.debug(s"[YouSign Webhook Validator] received : $receivedSignature")
            }

            // Constant-time comparison to prevent timing-attack side channels
            val expected = expectedSignature.getBytes("UTF-8")
            val received = receivedSignature.getBytes("UTF-8")

            if (MessageDigest.isEqual(expected, received)) {
              // Re-emit the already-consumed body so downstream plugins / the backend still see it
              Right(ctx.otoroshiRequest.copy(body = Source.single(bodyBytes)))
            } else {
              logger.warn("[YouSign Webhook Validator] invalid webhook signature")
              Left(Results.Unauthorized(Json.obj("error" -> "invalid signature")))
            }
          }
      }
    }
  }
}
