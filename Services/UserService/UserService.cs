using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace LoginRegisterJwt.Services.UserService;

[Route("api/[controller]")]
[ApiController]
public class UserService : IUserService
{
    private readonly IHttpContextAccessor _httpContextAccessor;

    public UserService(IHttpContextAccessor httpcontextAccessor)
    {
        _httpContextAccessor = httpcontextAccessor;
    }

    public string GetMyName()
    {
        var result = string.Empty;

        if(_httpContextAccessor.HttpContext != null)
        {
            result = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
        }
        return result;
    }
}
