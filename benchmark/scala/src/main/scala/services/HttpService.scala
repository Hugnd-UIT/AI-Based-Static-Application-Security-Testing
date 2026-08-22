package services
import scala.io.Source

object HttpService {
  def fetchUrl(url: String): String = {
    // Server-Side Request Forgery [CWE-918]
    Source.fromURL(url).mkString
  }
}
