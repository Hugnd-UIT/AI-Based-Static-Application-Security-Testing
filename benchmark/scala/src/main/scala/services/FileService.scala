package services
import scala.io.Source

object FileService {
  def readFile(filename: String): String = {
    // Path Traversal [CWE-22]
    val path = s"/var/www/uploads/$filename"
    Source.fromFile(path).getLines.mkString
  }
}
