package services
import sys.process._

object SystemService {
  def ping(ip: String): Unit = {
    // Command Injection [CWE-78]
    val cmd = s"ping -c 4 $ip"
    cmd.!
  }
}
