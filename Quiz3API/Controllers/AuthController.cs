using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Quiz3API.Models;
using Quiz3API.Utils;
using System.Data;

namespace Quiz3API.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly JwtService _jwtService = new JwtService();
        [HttpPost("login")]
        [APIKeyAuthorize]
        [EnableRateLimiting("LoginPolicy")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            if (model.Username == "admin")
            {
                var token = _jwtService.GenerateToken(model.Username, "Admin");
                _logger.LogWarning("Admin user '{Username}' with the role '{Role}' logged in successfully", model.Username, "Admin");
                return Ok(new { token });
            }
            else
            {
                var token = _jwtService.GenerateToken(model.Username, "User");
                _logger.LogWarning("User '{Username}' with the role '{Role}' logged in successfully", model.Username, "User");
                return Ok(new { token });
            }
        }

        private readonly ILogger<AuthController> _logger;

        public AuthController(ILogger<AuthController> logger)
        {
            _logger = logger;
        }
    }
}
