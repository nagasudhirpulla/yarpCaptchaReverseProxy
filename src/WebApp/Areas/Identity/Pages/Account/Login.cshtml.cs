using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Security.Claims;
using DNTCaptcha.Core;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;

namespace WebApp.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginModel : PageModel
    {
        private readonly ILogger<LoginModel> _logger;
        private readonly IDNTCaptchaValidatorService _validatorService;
        private readonly DNTCaptchaOptions _captchaOptions;

        public LoginModel(ILogger<LoginModel> logger, IDNTCaptchaValidatorService validatorService,
            IOptions<DNTCaptchaOptions> options)
        {
            _logger = logger;
            _validatorService = validatorService;
            _captchaOptions = options == null ? throw new ArgumentNullException(nameof(options)) : options.Value;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            //[Required]
            //[EmailAddress]
            public string Email { get; set; }

            //[Required]
            //[DataType(DataType.Password)]
            public string Password { get; set; }

            //[Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            if (!_validatorService.HasRequestValidCaptchaEntry(Language.English, DisplayMode.ShowDigits))
            {
                this.ModelState.AddModelError(_captchaOptions.CaptchaComponent.CaptchaInputName, "Please enter the security code as a number.");
            }

            if (ModelState.IsValid)
            {
                // Create a new identity with 2 claims based on the fields in the form
                var identity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, "Guest"),
                }, CookieAuthenticationDefaults.AuthenticationScheme);
                var principal = new ClaimsPrincipal(identity);

                return SignIn(principal, new AuthenticationProperties()
                {
                    RedirectUri = returnUrl
                }, CookieAuthenticationDefaults.AuthenticationScheme);
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }
    }
}
