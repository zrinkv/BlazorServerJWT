using BlazorAuthorization.Components.Pages.Areas.Identity.Models;
using BlazorAuthorization.Components.Pages.Areas.Identity.Services;
using Microsoft.AspNetCore.Components.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace BlazorAuthorization.SharedServices
{
    public class UserAuthenticationStateProvider : AuthenticationStateProvider, IDisposable
    {
        private readonly AuthUserService _authUserService;
        public User CurrentUser { get; private set; } = new();

        public UserAuthenticationStateProvider(AuthUserService blazorSchoolUserService)
        {
            _authUserService = blazorSchoolUserService;
            AuthenticationStateChanged += OnAuthenticationStateChangedAsync;
        }

        public async Task LoginAsync(string username, string password)
        {
            var principal = new ClaimsPrincipal();      
            
            var authResponse = await _authUserService.Login(new User { Username= username, Password = password });
            
            await _authUserService.PersistSessionTokenToBrowserAsync(authResponse.Token);
            var identity = new ClaimsIdentity(ParseClaimsFromJwt(authResponse.Token), "jwt");
            var userClaims = new ClaimsPrincipal(identity);
            var state = new AuthenticationState(userClaims);
            CurrentUser.FullName = identity.Name;

            NotifyAuthenticationStateChanged(Task.FromResult(state));          
        }

        public async Task LogoutAsync()
        {
            await _authUserService.ClearBrowserUserDataAsync();
            NotifyAuthenticationStateChanged(Task.FromResult(new AuthenticationState(new())));
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            ClaimsPrincipal _anonymous = new ClaimsPrincipal(new ClaimsIdentity());
            string token = null;
            try
            {
                token = await _authUserService.GetSessionTokenToBrowserAsync();
            }
            catch (Exception)
            {
            }

            if (string.IsNullOrEmpty(token) || IsTokenExpired(token))
            {
                return new AuthenticationState(_anonymous);
            }
            var identity = new ClaimsIdentity(ParseClaimsFromJwt(token), "jwt");

            var user = new ClaimsPrincipal(identity);
            CurrentUser = User.FromClaimsPrincipal(user);
            return await Task.FromResult(new AuthenticationState(user));
        }

        private async void OnAuthenticationStateChangedAsync(Task<AuthenticationState> task)
        {
            var authenticationState = await task;

            if (authenticationState is not null)
            {
                CurrentUser = User.FromClaimsPrincipal(authenticationState.User);
            }
        }

        public void Dispose() => AuthenticationStateChanged -= OnAuthenticationStateChangedAsync;

        //
        public static IEnumerable<Claim> ParseClaimsFromJwt(string token)
        {
            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);
            var claims = jwtSecurityToken.Claims.ToList();

            return claims;
        }

        private bool IsTokenExpired(string token)
        {
            JwtSecurityToken jwtSecurityToken;
            try
            {
                jwtSecurityToken = new JwtSecurityToken(token);
            }
            catch (Exception)
            {
                return false;
            }

            return jwtSecurityToken.ValidTo < DateTime.UtcNow;
        }
    }
}
