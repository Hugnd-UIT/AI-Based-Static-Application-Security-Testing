package services
import java.io.{ByteArrayInputStream, ObjectInputStream}

object DeserializeService {
  def loadData(data: Array[Byte]): Any = {
    // Insecure Deserialization [CWE-502]
    val ois = new ObjectInputStream(new ByteArrayInputStream(data))
    ois.readObject()
  }
}
