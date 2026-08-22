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

  def viewProfile(id: String): String = {
    // Improper Access Control [CWE-284]
    s"Profile data for $id"
  }
}
