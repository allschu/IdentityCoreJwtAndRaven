using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using IdentityCoreRaven.Models;
using Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Raven.Client.Documents;
using Raven.Client.Documents.Session;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace IdentityCoreRaven.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : RavenController
    {
        private readonly UserManager<CustomUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly RoleManager<Raven.Identity.IdentityRole> _roleManager;

        public AccountController(UserManager<CustomUser> userManager, RoleManager<Raven.Identity.IdentityRole> roleManager, IConfiguration configuration, IAsyncDocumentSession dbSession)
            : base(dbSession)
        {
            _configuration = configuration;
            _roleManager = roleManager;
            _userManager = userManager;
        }

        
        [HttpGet]
        [Authorize(Roles = CustomUser.AdminRole)]
        public async Task<IEnumerable<string>> GetAsync()
        {
            var users = await _userManager.Users.ToListAsync();

            return users.Select(x => x.Email).ToArray();
        }


        [HttpPost]
        [Authorize(Roles = CustomUser.AdminRole)]
        public async Task<IActionResult> PostAsync([FromBody] string value, CancellationToken cancellationToken)
        {
            var user = new CustomUser
            {
                UserName = value,
                Email = value
            };

            var creationResult = await _userManager.CreateAsync(user, "Welkom123!");

            if (!creationResult.Succeeded)
            {
                return BadRequest(creationResult.Errors);
            }

            // Add user to the manager role, change this to a role that makes sense
            var roleManagerResult = await this._userManager.AddToRoleAsync(user, CustomUser.ManagerRole);
            var roleResult = await this._userManager.AddToRoleAsync(user, CustomUser.AdminRole);

            if (!roleResult.Succeeded)
            {
                return BadRequest(roleResult.Errors);
            }

            return Ok();
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
                    audience: _configuration[""],
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
