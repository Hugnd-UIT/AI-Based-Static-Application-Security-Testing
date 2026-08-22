using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace Benchmark.CSharp.Services
{
    public class DeserializationService
    {
        public object DeserializeData(byte[] data)
        {
            // Insecure Deserialization [CWE-502]
            BinaryFormatter formatter = new BinaryFormatter();
            using (MemoryStream ms = new MemoryStream(data))
            {
                return formatter.Deserialize(ms);
            }
        }
    }
}
