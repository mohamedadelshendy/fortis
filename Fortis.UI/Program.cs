using System;
using Microsoft.Extensions.DependencyInjection;
using Photino.Blazor;
using Fortis.Client;

namespace Fortis.UI;

class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        var appBuilder = PhotinoBlazorAppBuilder.CreateDefault(args);

        // Register our Core C# Cryptography & Backend Services
        appBuilder.Services.AddSingleton<CryptoService>();
        
        // Make sure to replace these with the actual Supabase URL and Anon Key in production
        appBuilder.Services.AddSingleton(new SupabaseClient(
            supabaseUrl: "YOUR_SUPABASE_URL",
            supabaseAnonKey: "YOUR_SUPABASE_ANON_KEY"
        ));

        // Add the Root Component for Blazor
        appBuilder.RootComponents.Add<App>("#app");

        var app = appBuilder.Build();

        // Configure the native OS Window
        app.MainWindow
            .SetTitle("Fortis File Encryption")
            .SetSize(850, 650)
            .SetUseOsDefaultSize(false)
            .Center()
            .SetResizable(false); // Keeps the glassmorphism UI looking perfect

        AppDomain.CurrentDomain.UnhandledException += (sender, error) =>
        {
            app.MainWindow.ShowMessage("Fatal exception", error.ExceptionObject.ToString());
        };

        app.Run();
    }
}
