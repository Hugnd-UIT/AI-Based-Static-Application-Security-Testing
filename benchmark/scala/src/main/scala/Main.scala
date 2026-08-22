object Main extends App {
  println("Starting Scala Benchmark...")
  val controller = new controllers.ApiController()
  // Mocking the router
  controller.handleRequest("user", Map("id" -> "1"))
}
