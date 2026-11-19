namespace GuardianCaribe.Desktop.Services;

public sealed record LoginResult(bool Success, string Message);

public sealed class AuthenticationService
{
    public LoginResult ValidateLogin(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username))
            return new(false, "Introduzca su nombre de usuario.");

        if (string.IsNullOrWhiteSpace(password))
            return new(false, "Introduzca su contraseña.");

        return new(false, "Formulario validado. La autenticación real se habilitará al configurar la base de datos.");
    }
}
