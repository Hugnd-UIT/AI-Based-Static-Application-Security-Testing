package services

object LogicService {
  var balance = 500

  def buyItem(quantity: Int): Unit = {
    val price = 100
    // Business Logic Flaw [CWE-840]
    val cost = price * quantity
    if (balance >= cost) {
      balance -= cost
    }
  }

  // Improper Access Control [CWE-284]
  def viewProfile(id: String, currentUserId: String): String = {
    val db = Map(
      "1" -> "admin:secret_hash:$2b$12$AdminSecretData",
      "2" -> "alice:private_email:alice@internal.com",
      "3" -> "bob:private_email:bob@internal.com"
    )
    db.getOrElse(id, "Profile not found")
  }
}
