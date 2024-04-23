using BlazorAuthorization.Components.Pages.Areas.Identity.Models;
using BlazorAuthorization.SharedServices;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Newtonsoft.Json;

namespace BlazorAuthorization.Components.Pages.Areas.Identity.Services
{
    public class AuthUserService : BaseHttpClient
    {
        public AuthUserService(HttpClient httpClient, ProtectedSessionStorage protectedSessionStorage) : base(httpClient, protectedSessionStorage)
        {
        }

        //public User? LookupUserInDatabase(string username, string password)
        //{
        //    var usersFromDatabase = new List<User>()
        //    {
        //        new()
        //        {
        //            Username = "user",
        //            Password = "blazorschool"
        //        }
        //    };

        //    var foundUser = usersFromDatabase.SingleOrDefault(u => u.Username == username && u.Password == password);

        //    return foundUser;
        //}

        public async Task<AuthResponse?> Login(User request)
        {
            var result = await _httpClient.PostAsJsonAsync("Login/Login", request);
            if (result.IsSuccessStatusCode)
            {
                var content = await result.Content.ReadAsStringAsync();
                return JsonConvert.DeserializeObject<AuthResponse>(content);
            }
            else
            {
                return null;
            }
        }

    }
}
