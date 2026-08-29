package controllers

import services._
import org.apache.logging.log4j.LogManager
import com.fasterxml.jackson.databind.ObjectMapper
import org.apache.commons.text.StringSubstitutor
import org.yaml.snakeyaml.Yaml
import org.apache.commons.compress.archivers.zip.ZipArchiveInputStream

class ApiController {
  def handleRequest(route: String, params: Map[String, String]): Unit = {
    route match {
      case "user" => DbService.getUser(params("id"))
      case "ping" => SystemService.ping(params("ip"))
      case "read" => FileService.readFile(params("file"))
      case "fetch" => HttpService.fetchUrl(params("url"))
      case "hash" => CryptoService.hashData(params("data"))
      case "buy" => LogicService.buyItem(params("qty").toInt)
      case "profile" => LogicService.viewProfile(params("id"))
      case "xml" => XmlService.parseXml(params("xml"))
      case "deserialize" => DeserializeService.loadData(params("data").getBytes)
      case "sca" => 
        val payload = params.getOrElse("payload", "")
        
        // CVE-2021-44228 (log4j-core) Log4Shell
        org.apache.logging.log4j.LogManager.getLogger("").error(payload)
        
        // CVE-2019-16942 (jackson-databind)
        val mapper = new com.fasterxml.jackson.databind.ObjectMapper()
        mapper.enableDefaultTyping()
        mapper.readValue(payload, classOf[Object])
        
        // CVE-2022-42889 (commons-text) Text4Shell
        org.apache.commons.text.StringSubstitutor.createInterpolator().replace(payload)
        
        // CVE-2022-1471 (snakeyaml)
        new org.yaml.snakeyaml.Yaml().load(payload)
        
        // CVE-2021-36090 (commons-compress) OOM
        val zis = new org.apache.commons.compress.archivers.zip.ZipArchiveInputStream(new java.io.ByteArrayInputStream(payload.getBytes))
        while(zis.getNextZipEntry != null) {}
        
        println("SCA Executed")
      case _ => println("Not found")
    }
  }
}
