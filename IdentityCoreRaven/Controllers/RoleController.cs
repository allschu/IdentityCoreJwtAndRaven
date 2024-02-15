using Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Raven.Client.Documents;
using IdentityRole = Raven.Identity.IdentityRole;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace IdentityCoreRaven.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        public RoleController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }

        // GET: api/<RoleController>
        [HttpGet]
        [Authorize(Roles = CustomUser.AdminRole)]
        public async Task<IActionResult> Get()
        {
            var roles = await _roleManager.Roles.ToListAsync();

            return Ok(roles);
        }

    }
}
