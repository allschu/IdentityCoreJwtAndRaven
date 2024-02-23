using IdentityCoreRaven.Models;
using Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Raven.Client.Documents;
using Raven.Client.Documents.Session;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;


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


        /// <summary>
        /// Login the user, by generating a JWT token
        /// </summary>
        /// <param name="signInRequest"></param>
        /// <param name="cancellationToken"></param>
        /// <returns></returns>
        [HttpPost("generate-token")]
        public async Task<IActionResult> PostAsync(SignInRequest signInRequest, CancellationToken cancellationToken)
        {
            var user = await _userManager.FindByNameAsync(signInRequest.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, signInRequest.Password))
            {
                var token = await GenerateJwtSecurityToken(signInRequest.Email, user);
                var refresh = GenerateRefreshToken();

                if (!int.TryParse(_configuration["JwtSettings:RefreshTokenValidityInDays"],
                        out var refreshTokenValidityInDays))
                {
                    throw new InvalidOperationException("Invalid refresh token configuration");
                }

                user.RefreshToken = refresh;
                user.RefreshTokenExpiryTime = DateTime.Now.AddDays(refreshTokenValidityInDays);

                await _userManager.UpdateAsync(user);


                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    refreshToken = refresh,
                    expiration = token.ValidTo
                });
            }

            return Unauthorized();
        }

        /// <summary>
        /// Endpoint for the user to refresh the token
        /// </summary>
        /// <param name="refreshTokenRequest"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> RefreshToken(RefreshTokenRequest refreshTokenRequest)
        {
            var principal = GetPrincipalFromExpiredToken(refreshTokenRequest.AccessToken);
            if (principal == null)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            var user = await _userManager.FindByNameAsync(principal.Identity?.Name);

            //Check if the refresh token is valid and expected
            if (user.RefreshToken != refreshTokenRequest.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                return BadRequest("Invalid access token or refresh token");
            }

            var newAccessToken = await GenerateJwtSecurityToken(user.Email, user);
            var newRefreshToken = GenerateRefreshToken();

            //set the new refresh token
            user.RefreshToken = newRefreshToken;

            await _userManager.UpdateAsync(user);

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                refreshToken = newRefreshToken,
                expiration = newAccessToken.ValidTo
            });
        }

        /// <summary>
        /// Create a random refresh token
        /// </summary>
        /// <returns></returns>
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
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

        /// <summary>
        /// Generate a JWT token
        /// </summary>
        /// <param name="email"></param>
        /// <param name="user"></param>
        /// <returns></returns>
        private async Task<JwtSecurityToken> GenerateJwtSecurityToken(string email, CustomUser user)
        {
            var claims = new List<Claim>()
            {
                new (JwtRegisteredClaimNames.Sub, email),
                new (ClaimTypes.Name,email),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            await AddRolesClaims(claims, user);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:SigningKey"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);
            return token;
        }


        /// <summary>
        /// Decode token to get user ClaimsPrincipal
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        /// <exception cref="SecurityTokenException"></exception>
        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:SigningKey"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            if (securityToken is not JwtSecurityToken jwtSecurityToken || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;

        }
    }
}
