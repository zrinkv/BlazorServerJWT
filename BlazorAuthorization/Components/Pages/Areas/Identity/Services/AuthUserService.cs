using BlazorAuthorization.Components.Pages.Areas.Identity.Models;
using BlazorAuthorization.SharedServices;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Newtonsoft.Json;
using System.Net.Http.Headers;

namespace BlazorAuthorization.Components.Pages.Areas.Identity.Services
{
    public class AuthUserService : BaseHttpClient
    {
        public AuthUserService(HttpClient httpClient, ProtectedSessionStorage protectedSessionStorage) : base(httpClient, protectedSessionStorage)
        {
        }

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

        public async Task<string> GetData()
        {
            string token = await this.GetSessionTokenToBrowserAsync();
            if (!String.IsNullOrEmpty(token))
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var result = await _httpClient.GetAsync("Login/GetData");
            if (result.IsSuccessStatusCode)
            {
                var content = await result.Content.ReadAsStringAsync();
                //return JsonConvert.DeserializeObject<AuthResponse>(content);
                return content;
            }
            else
            {
                return null;
            }
        }

    }
}
