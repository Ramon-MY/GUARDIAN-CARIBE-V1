using System.Drawing;

namespace GuardianCaribe.Desktop.Theme;

public static class AppTheme
{
    public static readonly Color Background = Color.FromArgb(9, 17, 32);
    public static readonly Color Panel = Color.FromArgb(15, 27, 46);
    public static readonly Color Input = Color.FromArgb(25, 39, 61);
    public static readonly Color Accent = Color.FromArgb(0, 194, 224);
    public static readonly Color Text = Color.FromArgb(240, 247, 255);
    public static readonly Color Muted = Color.FromArgb(154, 174, 195);
    public static readonly Color Error = Color.FromArgb(255, 110, 120);

    public static Font Font(float size, FontStyle style = FontStyle.Regular) =>
        new("Segoe UI", size, style);
}
