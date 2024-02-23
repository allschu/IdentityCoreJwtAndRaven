using IdentityCoreRaven.Models.AccountViewModels;
using Infrastructure;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PagedList.Core;
using Raven.Client.Documents;
using Raven.Client.Documents.Session;

namespace IdentityCoreRaven.Controllers
{

    public class UserController : RavenController
    {
        private readonly UserManager<CustomUser> _userManager;
       
        public UserController(UserManager<CustomUser> userManager, IAsyncDocumentSession dbSession)
            : base(dbSession)
        {
            _userManager = userManager;
        }
        

        [HttpGet("all")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> GetAsync(CancellationToken cancellationToken)
        {
            var users = await _userManager.Users.ToListAsync(cancellationToken);

            return Ok(users.Select(x => x.Email).ToArray());
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Index(int? page, CancellationToken cancellationToken = default)
        {
            var pageNumber = page == null || page <= 0 ? 1 : page.Value;
            var pageSize = 5;

            var users = await _userManager.Users.ToArrayAsync(cancellationToken);

            var pagedList = new StaticPagedList<CustomUser>(users.Skip((pageNumber - 1) * pageSize).Take(pageSize), pageNumber, pageSize, users.Length);

            return View(pagedList);
        }

        [HttpGet]
        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> CreateAsync(RegisterViewModel model, CancellationToken cancellationToken = default)
        {
            if (ModelState.IsValid)
            {

                var user = new CustomUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    LastName = model.LastName,
                    FirstName = model.FirstName,
                };

                var creationResult = await _userManager.CreateAsync(user, model.Password);

                if (!creationResult.Succeeded)
                {
                    //Todo handle errors in ui
                }

                await this._userManager.AddToRoleAsync(user, CustomUser.UserRole);

                if (model.IsAdmin) //check if user needs to be admin
                {
                    var roleResult = await this._userManager.AddToRoleAsync(user, CustomUser.AdminRole);
                    if (!roleResult.Succeeded)
                    {
                        //todo 
                    }
                }
                
                return RedirectToAction("Index");
            }

            return View(model);
        }


    }
}
