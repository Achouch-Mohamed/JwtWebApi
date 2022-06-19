using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace JwtWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthentificationController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration _configuration;

        public AuthentificationController(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        [HttpPost]   
        public async Task<ActionResult<User>> Register(userDto request)
        {
            CreatePasswordHash(request.password,out byte[] passwordHash, out byte[] passwordSlat);
            user.UserName = request.UserName;       
            user.passwordHash = passwordHash;
            user.passwordSalt = passwordSlat;
            return Ok(user);
        }
        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(userDto request)
        {
            if (user.UserName != request.UserName) return BadRequest("User Not Fond !");
            if (!VerifyPasswordHash(request.password, user.passwordHash, user.passwordSalt))
            {
                return BadRequest("Password Wrong::::");
            }
            var token = CreateToken(user);
            return Ok(token);
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                 new Claim(ClaimTypes.Name,user.UserName)
            };
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value
                ));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha384Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires:DateTime.Now.AddDays(1),
                signingCredentials: creds);
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }
        private void CreatePasswordHash(string password,out  byte[] passwordHash,out byte[] passwordSlat)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSlat = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));  
            }
        }

        private bool VerifyPasswordHash(string password,byte[] passwordHash,byte[] passwordSlat)
        {
            using (var hmac = new HMACSHA512(passwordSlat))
            {             
               var comptedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return comptedHash.SequenceEqual(passwordHash);
            }
            
        }

    }
}
