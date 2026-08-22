using System.IO;

namespace Benchmark.CSharp.Services
{
    public class FileService
    {
        public string ReadUserFile(string filename)
        {
            // Path Traversal [CWE-22]
            string path = Path.Combine(@"C:\app\uploads\", filename);
            return File.ReadAllText(path);
        }
    }
}
