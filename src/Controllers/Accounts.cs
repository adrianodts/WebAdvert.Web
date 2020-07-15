using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.Runtime.Internal.Transform;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAdvert.Web.Models.Accounts;

public class Accounts : Controller
{
    private readonly SignInManager<CognitoUser> _siginManager;
    private readonly UserManager<CognitoUser> _userManager;
    private readonly CognitoUserPool _pool;
    public Accounts(SignInManager<CognitoUser> siginManager, UserManager<CognitoUser> userManager, 
        CognitoUserPool pool)
    {
        _siginManager = siginManager;
        _userManager = userManager;
        _pool = pool;
    }

    public IActionResult Index()
    {
        var model = new SignupModel();
        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> Signup(SignupModel model) 
    {
        if (ModelState.IsValid) 
        {
            var user = _pool.GetUser(model.Email);
            if (user.Status != null) 
            {
                ModelState.AddModelError("UserExists", "User with this email already exists");
                return View(model);
            }   

            user.Attributes.Add(CognitoAttribute.Name.AttributeName, model.Email);
            var createUser = await _userManager.CreateAsync(user, model.Password).ConfigureAwait(false);
            if (createUser.Succeeded) 
                return RedirectToAction("Confirm");
         }
        return View();
    }

    [HttpGet]
    public async Task<IActionResult> Signup() 
    {
        return View();
    }

    [HttpGet]
    public async Task<IActionResult> Confirm() 
    {
        var model = new ConfirmModel();
        return View(model);   
    }

    [HttpPost]
    public async Task<IActionResult> ConfirmPost(ConfirmModel model) 
    {
        if (ModelState.IsValid) 
        {
            var user = await _userManager.FindByEmailAsync(model.Email).ConfigureAwait(false); 
            if (user == null) 
            {
                ModelState.AddModelError("NotFound", "A user with given email address was not found");
                return View(model);
            }

            var result = await (_userManager as CognitoUserManager<CognitoUser>)
                .ConfirmSignUpAsync(user, model.Code, true)
                .ConfigureAwait(false);
            if (result.Succeeded) 
            {
                return RedirectToAction("Index", "Home");
            } 
            else 
            {
                foreach (var item in result.Errors)
                {
                    ModelState.AddModelError(item.Code, item.Description);
                }
            }
        }
        return View(model);    
    }

    [HttpGet]
    public async Task<IActionResult> Login(LoginModel model) {
        return View(model);
    }

    [HttpPost]
    [ActionName("Login")]
    public async Task<IActionResult> LoginPost(LoginModel model) 
    {
        if (ModelState.IsValid) 
        {
            var result = await _siginManager.PasswordSignInAsync(model.Email, 
                model.Password, model.RememberMe, false);

            if (result.Succeeded)
                return RedirectToAction("Index", "Home");
            else 
                ModelState.AddModelError("LoginError", "Email or password do not match");
        }   
        return View("Login", model); 
    }
}