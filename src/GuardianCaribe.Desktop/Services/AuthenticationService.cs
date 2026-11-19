using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace GuardianCaribe.Desktop.Services;

public sealed record AuthSession(string AccessToken, DateTimeOffset ExpiresAt)
{
    public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;
}

public sealed record LoginResult(AuthSession? Session, string Message)
{
    public bool Success => Session is not null;
}

public sealed class AuthenticationService
{
    private static readonly HttpClient Client = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly Uri apiBaseUri;

    public AuthenticationService()
    {
        var configured = Environment.GetEnvironmentVariable("GUARDIAN_CARIBE_API_URL")
            ?? "http://127.0.0.1:8000";
        if (!Uri.TryCreate(configured.TrimEnd('/') + "/", UriKind.Absolute, out var uri)
            || (uri.Scheme != Uri.UriSchemeHttps
                && !(uri.Scheme == Uri.UriSchemeHttp && IPAddress.TryParse(uri.Host, out var ip) && IPAddress.IsLoopback(ip)))
            || uri.UserInfo.Length > 0)
        {
            throw new InvalidOperationException(
                "La URL de la API debe usar HTTPS; HTTP solo está permitido en localhost.");
        }

        apiBaseUri = uri;
    }

    public async Task<LoginResult> LoginAsync(string username, string password, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(username))
            return new(null, "Introduzca su nombre de usuario.");
        if (string.IsNullOrWhiteSpace(password))
            return new(null, "Introduzca su contraseña.");

        try
        {
            using var response = await Client.PostAsJsonAsync(
                new Uri(apiBaseUri, "auth/login"),
                new LoginRequest(username.Trim(), password),
                cancellationToken);

            if (response.StatusCode == HttpStatusCode.Unauthorized
                || response.StatusCode == HttpStatusCode.Forbidden)
                return new(null, "Usuario o contraseña incorrectos.");

            if (!response.IsSuccessStatusCode)
                return new(null, $"La API respondió con el estado {(int)response.StatusCode}.");

            var token = await response.Content.ReadFromJsonAsync<TokenResponse>(cancellationToken: cancellationToken);
            if (string.IsNullOrWhiteSpace(token?.AccessToken) || token.ExpiresIn <= 0)
                return new(null, "La API devolvió una respuesta de autenticación no válida.");

            return new(new AuthSession(token.AccessToken, DateTimeOffset.UtcNow.AddSeconds(token.ExpiresIn)),
                "Autenticación correcta.");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(null, "La API tardó demasiado en responder.");
        }
        catch (HttpRequestException)
        {
            return new(null, "No se pudo conectar con la API. Verifique que el backend esté activo.");
        }
        catch (JsonException)
        {
            return new(null, "La API devolvió una respuesta que no se pudo leer.");
        }
    }

    private sealed record LoginRequest(string Username, string Password);
    private sealed record TokenResponse(string AccessToken, int ExpiresIn);
}
