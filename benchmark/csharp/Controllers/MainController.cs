using Microsoft.AspNetCore.Mvc;
using Benchmark.CSharp.Services;

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
    }
}
