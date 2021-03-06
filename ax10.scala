//> using scala "3.1.1"
//> using lib "dev.zio::zio:2.0.0-RC2"

// ax10-updated.scala has this example updates for ZIO 2.0.0

import zio._
import zio.Console._
import java.awt.Taskbar
import javax.crypto.Mac
import java.util.Base64
import javax.crypto.spec.SecretKeySpec
import javax.crypto.SecretKey

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
  val layer: URLayer[Mac, Hasher] = (HasherLive(_)).toLayer

}

// Not everything needs to be/fit a Service Module pattern
object HashHelper {

  def hmac512: ZLayer[SecretKeySpec, Throwable, Mac] = {
    (
      for {
        mac     <- ZIO.effect(Mac.getInstance("HmacSHA512"))
        keySpec <- ZIO.service[SecretKeySpec]
        _       <- ZIO.effect(mac.init(keySpec))
      } yield mac
    ).toLayer
  }

  def specForKey512(key: String): ZLayer[Any, Throwable, SecretKeySpec] = {
    ZIO.effect(new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA512")).toLayer
  }

  def base64Encode(bytes: Array[Byte]): Task[String] =
    ZIO.attempt(Base64.getUrlEncoder.withoutPadding().encodeToString(bytes))

}

object HashApp extends ZIOAppDefault {

  val superSecretKey: String = "abc123"

  // The overall flow of our program
  val program: ZIO[ZIOAppArgs & (Hasher & Console), Throwable, ExitCode] = for {
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
              ZIO.ifM(Hasher.validate(args.head, superSecretKey, args.last))(
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

  def run = program
    .catchAll(err => printLine(err.getMessage))
    .provideSomeLayer(appLayer)

}
