using System.Security.Cryptography;
using System.Text;

namespace Benchmark.CSharp.Services
{
    public class CryptoService
    {
        public string HashData(string input)
        {
            // Broken Crypto Algorithm [CWE-327]
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.ASCII.GetBytes(input);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return Encoding.ASCII.GetString(hashBytes);
            }
        }

        public void EncryptToken()
        {
            // Hardcoded Key [CWE-321]
            string key = "S3cr3t_K3y_1234567890";
            // Use key for encryption...
        }
    }
}
