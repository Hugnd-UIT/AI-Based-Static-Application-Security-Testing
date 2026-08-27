using System.Net.Http;
using System.Threading.Tasks;

namespace Benchmark.CSharp.Services
{
    public class HttpService
    {
        private static readonly HttpClient client = new HttpClient();

        public async Task<string> FetchResource(string url)
        {
            // Server-Side Request Forgery [CWE-918]
            HttpResponseMessage response = await client.GetAsync(url);
            return await response.Content.ReadAsStringAsync();
        }
    }
}
