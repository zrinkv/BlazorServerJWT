using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using System.Net.Http.Headers;

namespace BlazorAuthorization.SharedServices
{
    public class BaseHttpClient
    {
        private readonly string _sessionStorageKey = "IdentityToken";
        protected readonly HttpClient _httpClient;
        private readonly ProtectedSessionStorage _protectedSessionStorage;        

        public BaseHttpClient(HttpClient httpClient, ProtectedSessionStorage SessionStorage)
        {
            _httpClient = httpClient;            
            _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _protectedSessionStorage = SessionStorage;
        }

        public async Task<string> GetSessionTokenToBrowserAsync()
        {
            var sessionTokenResult = await _protectedSessionStorage.GetAsync<string>(_sessionStorageKey);         

            if (sessionTokenResult.Success && !string.IsNullOrEmpty(sessionTokenResult.Value))
            {                
                return sessionTokenResult.Value;
            }
            else
                return null;
        }        

        public async Task PersistSessionTokenToBrowserAsync(string SessionToken)
        {            
            await _protectedSessionStorage.SetAsync(_sessionStorageKey, SessionToken);
        }       

        public async Task ClearBrowserUserDataAsync() => await _protectedSessionStorage.DeleteAsync(_sessionStorageKey);
    }
}
