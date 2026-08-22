using Microsoft.AspNetCore.Mvc;

namespace Benchmark.CSharp.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        [HttpGet("login")]
        public IActionResult LoginRedirect(string returnUrl)
        {
            // Open Redirect [CWE-601]
            return Redirect(returnUrl);
        }
    }
}
