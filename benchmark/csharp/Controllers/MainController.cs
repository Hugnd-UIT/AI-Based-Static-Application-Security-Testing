using Microsoft.AspNetCore.Mvc;
using Benchmark.CSharp.Services;
using Newtonsoft.Json;
using log4net;
using System.Data.SqlClient;
using System.Text.Encodings.Web;
using System.Net.Http;

namespace Benchmark.CSharp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class MainController : ControllerBase
    {
        private readonly DatabaseService _dbService = new DatabaseService();
        private readonly SystemUtils _systemUtils = new SystemUtils();
        private readonly FileService _fileService = new FileService();
        private readonly XmlService _xmlService = new XmlService();
        private readonly CryptoService _cryptoService = new CryptoService();
        private readonly HttpService _httpService = new HttpService();
        private readonly LdapService _ldapService = new LdapService();
        private readonly DeserializationService _deserializationService = new DeserializationService();

        [HttpGet("user")]
        public IActionResult GetUser(string id)
        {
            _dbService.GetUserById(id);
            return Ok();
        }

        [HttpGet("ping")]
        public IActionResult Ping(string ip)
        {
            _systemUtils.PingTarget(ip);
            return Ok();
        }

        [HttpGet("read")]
        public IActionResult ReadFile(string filename)
        {
            return Ok(_fileService.ReadUserFile(filename));
        }

        [HttpPost("parse")]
        public IActionResult ParseXml([FromBody] string xml)
        {
            _xmlService.ParseXmlData(xml);
            return Ok();
        }

        [HttpPost("deserialize")]
        public IActionResult Deserialize([FromBody] byte[] data)
        {
            return Ok(_deserializationService.DeserializeData(data));
        }

        [HttpGet("hash")]
        public IActionResult Hash(string data)
        {
            _cryptoService.EncryptToken(); // Calls hardcoded key function
            return Ok(_cryptoService.HashData(data));
        }

        [HttpGet("fetch")]
        public async System.Threading.Tasks.Task<IActionResult> Fetch(string url)
        {
            return Ok(await _httpService.FetchResource(url));
        }

        [HttpGet("search")]
        public IActionResult SearchLdap(string username)
        {
            _ldapService.FindUser(username);
            return Ok();
        }

        [HttpGet("sca")]
        public async System.Threading.Tasks.Task<IActionResult> Sca(string payload)
        {
            // CVE-2024-21907 (Newtonsoft.Json)
            Newtonsoft.Json.JsonConvert.DeserializeObject<object>(payload, new Newtonsoft.Json.JsonSerializerSettings { TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All });
            
            // CVE-2018-1285 (log4net XXE)
            log4net.Config.XmlConfigurator.Configure(new System.IO.MemoryStream(System.Text.Encoding.UTF8.GetBytes(payload)));
            
            // CVE-2022-41064 (System.Data.SqlClient)
            var conn = new System.Data.SqlClient.SqlConnection("Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;");
            conn.Open();
            var cmd = new System.Data.SqlClient.SqlCommand(payload, conn);
            await cmd.ExecuteReaderAsync();
            
            // CVE-2021-26701 (System.Text.Encodings.Web)
            System.Text.Encodings.Web.JavaScriptEncoder.Default.Encode(payload);
            
            // CVE-2018-8292 (System.Net.Http)
            var client = new System.Net.Http.HttpClient();
            client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", payload);
            await client.GetAsync("http://example.com/redirect");
            
            return Ok();
        }
    }
}
