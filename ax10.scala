//> using scala "3.1.1"
//> using lib "dev.zio::zio:2.0.0-RC2"

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

case class MacHasher(mac: Mac) extends Hasher {

  override def hash(message: String, key: String): Task[String] =
    for {
      hash <- ZIO.attempt(mac.doFinal(message.getBytes("UTF-8")))
      encoded <- B64.base64Encode(hash)
    } yield encoded

  override def validate(
      message: String,
      key: String,
      msgHash: String
  ): Task[Boolean] =
    for {
      hash <- ZIO.attempt(mac.doFinal(message.getBytes("UTF-8")))
      encoded <- B64.base64Encode(hash)
    } yield encoded == msgHash

}

object Hasher {

  def hash(message: String, key: String): RIO[Hasher, String] =
    ZIO.serviceWithZIO[Hasher](_.hash(message, key))

  def validate(
      message: String,
      key: String,
      hash: String
  ): RIO[Hasher, Boolean] =
    ZIO.serviceWithZIO[Hasher](_.validate(message, key, hash))

  def specForKey512(key: String): ZLayer[Any, Throwable, SecretKeySpec] = {
    ZIO.effect(new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA512")).toLayer
  }

  val layer: URLayer[Mac, Hasher] = (MacHasher(_)).toLayer

}

object HashHelper {

  def hmac512: ZLayer[SecretKeySpec, Throwable, Mac] = {
    (
      for {
        mac <- ZIO.effect(Mac.getInstance("HmacSHA512"))
        keySpec <- ZIO.service[SecretKeySpec]
        _ <- ZIO.effect(mac.init(keySpec))
      } yield mac
    ).toLayer
  }

  def specForKey512(key: String): ZLayer[Any, Throwable, SecretKeySpec] = {
    ZIO.effect(new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA512")).toLayer
  }

}

object B64 {
  def base64Encode(bytes: Array[Byte]): Task[String] =
    ZIO.attempt(Base64.getUrlEncoder.withoutPadding().encodeToString(bytes))

  def base64Encode(str: String): Task[String] =
    ZIO.attempt(
      Base64.getUrlEncoder
        .withoutPadding()
        .encodeToString(str.getBytes("UTF-8"))
    )

  def base64Decode(str: String): Task[String] =
    ZIO.attempt(new String(Base64.getUrlDecoder.decode(str)))

  def base64DecodeToBytes(str: String): Task[Array[Byte]] =
    ZIO.attempt(Base64.getUrlDecoder.decode(str))
}

object HashApp extends ZIOAppDefault {

  val superSecretKey: String = "abc123"

  val program: ZIO[ZIOAppArgs & (Hasher & Console), Throwable, ExitCode] = for {
    args <- ZIOAppArgs.getArgs
    _ <- ZIO.cond(
      args.size == 1 || args.size == 2,
      (),
      new Exception("This app requires one argument to hash, and 2 to validate")
    )
    _ <- ZIO.when(args.size == 1) {
      Hasher.hash(args.head, superSecretKey).flatMap(h => printLine(h))
    }
    _ <- ZIO.when(args.size == 2) {
      ZIO.ifM(Hasher.validate(args.head, superSecretKey, args.last))(
        onTrue = printLine("valid"),
        onFalse = printLine("invalid")
      )
    }
  } yield ExitCode.success

  val appLayer: ZLayer[Any, Nothing, Hasher] = {
    (HashHelper.specForKey512(
      superSecretKey
    ) >>> HashHelper.hmac512) >>> Hasher.layer
  }.orDie

  def run = program
    .catchAll(err => printLine(err.getMessage))
    .provideSomeLayer(appLayer)

}
