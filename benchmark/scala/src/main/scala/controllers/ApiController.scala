package controllers

import services._

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
        
        // log4j-core
        org.apache.logging.log4j.LogManager.getLogger("").info(payload)
        
        // jackson-databind
        new com.fasterxml.jackson.databind.ObjectMapper().readValue(payload, classOf[Object])
        
        // commons-text
        org.apache.commons.text.StringSubstitutor.createInterpolator().replace(payload)
        
        // snakeyaml
        new org.yaml.snakeyaml.Yaml().load(payload)
        
        // commons-compress
        new org.apache.commons.compress.archivers.zip.ZipArchiveInputStream(new java.io.ByteArrayInputStream(payload.getBytes))
        
        println("SCA Executed")
      case _ => println("Not found")
    }
  }
}
