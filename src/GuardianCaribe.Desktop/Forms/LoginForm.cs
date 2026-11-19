using GuardianCaribe.Desktop.Services;
using GuardianCaribe.Desktop.Theme;

namespace GuardianCaribe.Desktop.Forms;

public sealed class LoginForm : Form
{
    private AuthSession? session;
    private readonly Panel leftPanel = new();
    private readonly Panel rightPanel = new();
    private readonly Panel loginCard = new();
    private readonly TextBox txtUsername = new();
    private readonly TextBox txtPassword = new();
    private readonly Label lblMessage = new();
    private readonly CheckBox chkShowPassword = new();
    private readonly Button btnLogin = new();

    public LoginForm()
    {
        Text = "GUARDIÁN CARIBE | Acceso seguro";
        StartPosition = FormStartPosition.CenterScreen;
        MinimumSize = new Size(850, 600);
        Size = new Size(1120, 720);
        BackColor = AppTheme.Background;
        Font = AppTheme.Font(10);
        DoubleBuffered = true;
        BuildInterface();
        Resize += (_, _) => UpdateLayout();
        Shown += (_, _) => txtUsername.Focus();
        AcceptButton = btnLogin;
    }

    private void BuildInterface()
    {
        leftPanel.BackColor = AppTheme.Background;
        rightPanel.BackColor = AppTheme.Panel;
        Controls.Add(leftPanel);
        Controls.Add(rightPanel);
        BuildBranding();
        BuildLoginCard();
        UpdateLayout();
    }

    private void BuildBranding()
    {
        var logo = new Label
        {
            Text = "◆",
            Font = AppTheme.Font(46, FontStyle.Bold),
            ForeColor = AppTheme.Accent,
            AutoSize = true,
            Location = new Point(56, 90)
        };
        var title = new Label
        {
            Text = "GUARDIÁN\nCARIBE",
            Font = AppTheme.Font(34, FontStyle.Bold),
            ForeColor = AppTheme.Text,
            AutoSize = true,
            Location = new Point(56, 175)
        };
        var subtitle = new Label
        {
            Text = "Plataforma de monitoreo,\nanálisis y protección digital.",
            Font = AppTheme.Font(14),
            ForeColor = AppTheme.Muted,
            AutoSize = true,
            Location = new Point(59, 325)
        };
        var line = new Panel
        {
            BackColor = AppTheme.Accent,
            Size = new Size(65, 4),
            Location = new Point(59, 415)
        };
        var footer = new Label
        {
            Text = "SEGURIDAD  •  INTELIGENCIA  •  CONTROL",
            Font = AppTheme.Font(9, FontStyle.Bold),
            ForeColor = AppTheme.Muted,
            AutoSize = true,
            Location = new Point(59, 450)
        };
        leftPanel.Controls.AddRange(new Control[] { logo, title, subtitle, line, footer });
    }

    private void BuildLoginCard()
    {
        loginCard.Size = new Size(390, 480);
        loginCard.BackColor = AppTheme.Panel;
        rightPanel.Controls.Add(loginCard);

        var heading = new Label
        {
            Text = "Bienvenido",
            Font = AppTheme.Font(25, FontStyle.Bold),
            ForeColor = AppTheme.Text,
            Location = new Point(0, 0),
            Size = new Size(390, 48)
        };
        var description = new Label
        {
            Text = "Inicia sesión para acceder al sistema.",
            Font = AppTheme.Font(10),
            ForeColor = AppTheme.Muted,
            Location = new Point(2, 58),
            Size = new Size(385, 30)
        };
        var userLabel = CreateLabel("USUARIO", 112);
        ConfigureTextBox(txtUsername, "Nombre de usuario", 143);
        var passwordLabel = CreateLabel("CONTRASEÑA", 215);
        ConfigureTextBox(txtPassword, "Contraseña", 246);
        txtPassword.UseSystemPasswordChar = true;

        chkShowPassword.Text = "Mostrar contraseña";
        chkShowPassword.ForeColor = AppTheme.Muted;
        chkShowPassword.BackColor = AppTheme.Panel;
        chkShowPassword.Font = AppTheme.Font(9);
        chkShowPassword.Location = new Point(0, 310);
        chkShowPassword.Size = new Size(200, 28);
        chkShowPassword.CheckedChanged += (_, _) =>
            txtPassword.UseSystemPasswordChar = !chkShowPassword.Checked;

        btnLogin.Text = "INICIAR SESIÓN";
        btnLogin.Size = new Size(390, 52);
        btnLogin.Location = new Point(0, 354);
        btnLogin.BackColor = AppTheme.Accent;
        btnLogin.ForeColor = AppTheme.Background;
        btnLogin.FlatStyle = FlatStyle.Flat;
        btnLogin.FlatAppearance.BorderSize = 0;
        btnLogin.Font = AppTheme.Font(11, FontStyle.Bold);
        btnLogin.Cursor = Cursors.Hand;
        btnLogin.Click += LoginAsync;

        lblMessage.Location = new Point(0, 417);
        lblMessage.Size = new Size(390, 58);
        lblMessage.ForeColor = AppTheme.Error;
        lblMessage.Font = AppTheme.Font(9);

        loginCard.Controls.AddRange(new Control[]
        {
            heading, description, userLabel, txtUsername,
            passwordLabel, txtPassword, chkShowPassword,
            btnLogin, lblMessage
        });
    }

    private static Label CreateLabel(string text, int y) => new()
    {
        Text = text,
        Font = AppTheme.Font(9, FontStyle.Bold),
        ForeColor = AppTheme.Muted,
        Location = new Point(0, y),
        Size = new Size(390, 25)
    };

    private static void ConfigureTextBox(TextBox box, string placeholder, int y)
    {
        box.Size = new Size(390, 42);
        box.Location = new Point(0, y);
        box.BackColor = AppTheme.Input;
        box.ForeColor = AppTheme.Text;
        box.BorderStyle = BorderStyle.FixedSingle;
        box.Font = AppTheme.Font(12);
        box.PlaceholderText = placeholder;
        box.MaxLength = 128;
    }

    private async void LoginAsync(object? sender, EventArgs e)
    {
        btnLogin.Enabled = false;
        btnLogin.Text = "CONECTANDO…";
        lblMessage.ForeColor = AppTheme.Muted;
        lblMessage.Text = "Conectando con el servicio de autenticación…";

        try
        {
            LoginResult result = await new AuthenticationService()
                .LoginAsync(txtUsername.Text, txtPassword.Text);
            session = result.Session;
            lblMessage.ForeColor = result.Success ? AppTheme.Accent : AppTheme.Error;
            lblMessage.Text = result.Message;
            txtPassword.Clear();

            if (session is not null)
            {
                txtUsername.Enabled = false;
                txtPassword.Enabled = false;
                chkShowPassword.Enabled = false;
                btnLogin.Text = "SESIÓN INICIADA";
            }
        }
        catch (InvalidOperationException ex)
        {
            lblMessage.ForeColor = AppTheme.Error;
            lblMessage.Text = ex.Message;
        }
        finally
        {
            if (session is null)
            {
                btnLogin.Enabled = true;
                btnLogin.Text = "INICIAR SESIÓN";
            }
        }
    }

    private void UpdateLayout()
    {
        int width = ClientSize.Width;
        int height = ClientSize.Height;
        int leftWidth = (int)(width * 0.48);
        leftPanel.SetBounds(0, 0, leftWidth, height);
        rightPanel.SetBounds(leftWidth, 0, width - leftWidth, height);
        loginCard.Left = Math.Max(20, (rightPanel.Width - loginCard.Width) / 2);
        loginCard.Top = Math.Max(20, (rightPanel.Height - loginCard.Height) / 2);
    }
}
