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
      case _ => println("Not found")
    }
  }
}
