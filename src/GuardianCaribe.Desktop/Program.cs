using GuardianCaribe.Desktop.Forms;

namespace GuardianCaribe.Desktop;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new LoginForm());
    }
}
