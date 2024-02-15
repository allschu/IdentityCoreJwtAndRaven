using IdentityCoreRaven.Models;
using Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Raven.Client.Documents.Session;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Raven.Client.Documents;

namespace IdentityCoreRaven.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class JwtController : RavenController
    {
        private readonly UserManager<CustomUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly RoleManager<Raven.Identity.IdentityRole> _roleManager;

        public JwtController(UserManager<CustomUser> userManager, RoleManager<Raven.Identity.IdentityRole> roleManager, IConfiguration configuration, IAsyncDocumentSession dbSession)
            : base(dbSession)
        {
            _configuration = configuration;
            _roleManager = roleManager;
            _userManager = userManager;
        }


        [HttpGet]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> GetAsync(CancellationToken cancellationToken)
        {
            var users = await _userManager.Users.ToListAsync(cancellationToken);

            return Ok(users.Select(x => x.Email).ToArray());
        }

        /// <summary>
        /// Login the user, by generating a JWT token
        /// </summary>
        /// <param name="signInRequest"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        [HttpPost("login")]
        public async Task<IActionResult> PostAsync(SignInRequest signInRequest, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByNameAsync(signInRequest.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, signInRequest.Password))
            {
                var claims = new List<Claim>()
                {
                    new (JwtRegisteredClaimNames.Sub, signInRequest.Email),
                    new (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                await AddRolesClaims(claims, user);

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["SigningKey"]));
                var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

                var token = new JwtSecurityToken(
                    issuer: _configuration["JwtSettings:Issuer"],
                    audience: _configuration["JwtSettings:Audience"],
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(30),
                    signingCredentials: creds);

                return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
            }

            return Unauthorized();
        }

        /// <summary>
        /// Creates a list of claims for the user roles
        /// </summary>
        /// <param name="claims"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private async Task AddRolesClaims(IList<Claim> claims, CustomUser user)
        {
            var userRoles = await _userManager.GetRolesAsync(user);

            // Add each role as a claim
            foreach (var userRole in userRoles)
            {
                claims.Add(new Claim("roles", userRole));

                var role = await _roleManager.FindByNameAsync(userRole);
                if (role == null)
                    continue;

                var roleClaims = await _roleManager.GetClaimsAsync(role);
                foreach (var roleClaim in roleClaims)
                {
                    claims.Add(roleClaim);
                }
            }
        }
    }
}
