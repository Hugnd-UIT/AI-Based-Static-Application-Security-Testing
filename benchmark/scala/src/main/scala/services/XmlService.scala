package services
import scala.xml.XML

object XmlService {
  def parseXml(xmlString: String): Unit = {
    // XML External Entity [CWE-611]
    val xml = XML.loadString(xmlString)
    println(xml)
  }
}
