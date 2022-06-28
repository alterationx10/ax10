//> using scala "3.1.3"
//> using lib "dev.zio::zio:2.0.0"

import zio._
import zio.Console._
import java.awt.Taskbar
import javax.crypto.Mac
import java.util.Base64
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKey
import java.io.IOException

// Hash-based message authentication code
trait Hasher {
  def hash(message: String, key: String): Task[String]
  def validate(message: String, key: String, hash: String): Task[Boolean]
}

// The live, default implementation of our Hasher Service.
case class HasherLive(mac: Mac) extends Hasher {

  override def hash(message: String, key: String): Task[String] =
    for {
      hash    <- ZIO.attempt(mac.doFinal(message.getBytes("UTF-8")))
      encoded <- HashHelper.base64Encode(hash)
    } yield encoded

  override def validate(
      message: String,
      key: String,
      msgHash: String
  ): Task[Boolean] =
    for {
      hash    <- ZIO.attempt(mac.doFinal(message.getBytes("UTF-8")))
      encoded <- HashHelper.base64Encode(hash)
    } yield encoded == msgHash

}

// Companion object with accessors
object Hasher {

  def hash(message: String, key: String): RIO[Hasher, String] =
    ZIO.serviceWithZIO[Hasher](_.hash(message, key))

  def validate(
      message: String,
      key: String,
      hash: String
  ): RIO[Hasher, Boolean] =
    ZIO.serviceWithZIO[Hasher](_.validate(message, key, hash))

  // Reference implementation layer
  val layer: URLayer[Mac, Hasher] = ZLayer.fromFunction(HasherLive.apply _)

}

// Not everything needs to be/fit a Service Module pattern
object HashHelper {

  def hmac512: ZLayer[SecretKeySpec, Throwable, Mac] = {
    ZLayer.fromZIO(
      for {
        mac     <- ZIO.attempt(Mac.getInstance("HmacSHA512"))
        keySpec <- ZIO.service[SecretKeySpec]
        _       <- ZIO.attempt(mac.init(keySpec))
      } yield mac
    )
  }

  def specForKey512(key: String): ZLayer[Any, Throwable, SecretKeySpec] = {
    ZLayer.fromZIO(
      ZIO.attempt(new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA512"))
    )
  }

  def base64Encode(bytes: Array[Byte]): Task[String] =
    ZIO.attempt(Base64.getUrlEncoder.withoutPadding().encodeToString(bytes))

}

object HashApp extends ZIOAppDefault {

  val superSecretKey: String = "abc123"

  // The overall flow of our program
  val program: ZIO[ZIOAppArgs & Hasher, Throwable, ExitCode] = for {
    // Read the arguments
    args <- ZIOAppArgs.getArgs
    // Make sure we've been passed only 1 or 2 args
    _    <- ZIO.cond(
              args.size == 1 || args.size == 2,
              (),
              new Exception(
                "This app requires 1 argument to hash, and 2 to validate"
              )
            )
    // When we've been passed 1 arg, hash it
    _    <- ZIO.when(args.size == 1) {
              Hasher.hash(args.head, superSecretKey).flatMap(h => printLine(h))
            }
    // When we've been passed 2 args, verify it.
    _    <- ZIO.when(args.size == 2) {
              ZIO.ifZIO(Hasher.validate(args.head, superSecretKey, args.last))(
                onTrue = printLine("valid"),
                onFalse = printLine("invalid")
              )
            }
  } yield ExitCode.success

  // We call .orDie here to give up, instead of having an something in the error channel,
  // because if we can't construct our dependencies, our app isn't going to
  // work anyway.
  val appLayer: ZLayer[Any, Nothing, Hasher] = {
    (HashHelper.specForKey512(
      superSecretKey
    ) >>> HashHelper.hmac512) >>> Hasher.layer
  }.orDie

  // ZIOAppDefault will likely provide the following type signature for auto-complete
  //   override def run: ZIO[Any & (ZIOAppArgs & Scope), Any, Any]
  //   Which flows from ZIOApp
  //   def run: ZIO[Environment with ZIOAppArgs with Scope, Any, Any],
  //   but, you can probably trim that and remove things you're not using (i.e. Scope here)

  // .provideSomeLayer[SomeDep](...allTheOtherDeps) will build a layer that provides everything but SomeDep.
  // Here, that means the run of ZioAppDefault is going to provide ZIOAppArgs for us.
  override def run: ZIO[ZIOAppArgs, Any, Any] =
    program
      .catchAll(err => printLine(err.getMessage))
      .provideSomeLayer[ZIOAppArgs](appLayer)

}
