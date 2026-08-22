package services

object DbService {
  def getUser(id: String): Unit = {
    // SQL Injection [CWE-89]
    val query = s"SELECT * FROM users WHERE id = '$id'"
    println(s"Executing: $query")
  }
}
