using Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Raven.Client.Documents;

namespace IdentityCoreRaven.Controllers
{
    [Authorize]
    public class UserController : Controller
    {
        private readonly UserManager<CustomUser> _userManager;
       
        public UserController(UserManager<CustomUser> userManager)
        {
            _userManager = userManager;
        }

        [HttpGet]
        public async Task<IActionResult> Index(CancellationToken cancellationToken = default)
        {
            var users = await _userManager.Users.ToListAsync(cancellationToken);
            
            return View(users);
        }

        [HttpPost]
        public async Task<IActionResult> Create([FromBody] string value, CancellationToken cancellationToken)
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
            var roleUserResult = await this._userManager.AddToRoleAsync(user, CustomUser.UserRole);
            var roleResult = await this._userManager.AddToRoleAsync(user, CustomUser.AdminRole);

            if (!roleResult.Succeeded)
            {
                return BadRequest(roleResult.Errors);
            }

            return Ok();
        }


    }
}
