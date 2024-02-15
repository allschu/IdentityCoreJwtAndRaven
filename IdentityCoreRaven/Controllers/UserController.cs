using IdentityCoreRaven.Models.AccountViewModels;
using Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Raven.Client.Documents;
using Raven.Client.Documents.Session;

namespace IdentityCoreRaven.Controllers
{
    [Authorize]
    public class UserController : RavenController
    {
        private readonly UserManager<CustomUser> _userManager;
       
        public UserController(UserManager<CustomUser> userManager, IAsyncDocumentSession dbSession)
            : base(dbSession)
        {
            _userManager = userManager;
        }

        [HttpGet]
        public async Task<IActionResult> Index(CancellationToken cancellationToken = default)
        {
            var users = await _userManager.Users.ToListAsync(cancellationToken);
            
            return View(users);
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
                    FirstName = model.FirstName
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
