using Microsoft.AspNetCore.Mvc;

namespace IdentityCoreRaven.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
