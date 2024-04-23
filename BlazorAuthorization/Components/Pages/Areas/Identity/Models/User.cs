using System.Security.Claims;

namespace BlazorAuthorization.Components.Pages.Areas.Identity.Models
{
    public class User
    {
        public string Username { get; set; } = "";
        public string Password { get; set; } = "";
        public string FullName { get; set; } = "Not logged user";
        public string EmailAddress { get; set; } = string.Empty;

        public static User FromClaimsPrincipal(ClaimsPrincipal principal) => new()
        {
            Username = principal.FindFirstValue(ClaimTypes.Name),
            Password = principal.FindFirstValue(ClaimTypes.Hash),
            FullName = principal.FindFirstValue("FirstNameLastName")
        };
    }
}
