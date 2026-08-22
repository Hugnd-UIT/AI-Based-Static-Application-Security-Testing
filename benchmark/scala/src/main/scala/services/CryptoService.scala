package services
import java.security.MessageDigest

object CryptoService {
  def hashData(data: String): String = {
    // Broken Crypto Algorithm [CWE-327]
    val md5 = MessageDigest.getInstance("MD5")
    md5.digest(data.getBytes).map("%02x".format(_)).mkString
  }

  def encryptData(): Unit = {
    // Hardcoded Key [CWE-321]
    val key = "S3cr3t_K3y_1234567890"
    println(s"Using key: $key")
  }
}
