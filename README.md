# Fortis - Secure File Encryption

Fortis is a desktop application built with Photino and Blazor for highly secure file encryption. It employs a distributed key architecture (inspired by Shamir's Secret Sharing) where the decryption key is split into multiple shares. One share is stored locally, while the other is stored securely in Supabase and requires an Email OTP to retrieve.

## Features
- **Cross-Platform Desktop UI**: Powered by Photino and Blazor.
- **High Security**: AES-256 encryption with PBKDF2 key derivation.
- **Distributed Key Storage**: A master key is never stored in one place. You need your password, your local KeyShare_A, and the remote KeyShare_B.
- **MFA Decryption**: Integration with Supabase Edge Functions and Resend to verify decryption requests via One-Time Passwords (OTP).

## Setup Instructions

### 1. Supabase Backend Setup
1. Create a new Supabase project.
2. Run the SQL migrations found in `supabase/migrations/` in your Supabase SQL Editor to create the necessary tables (`encrypted_files` and `file_otps`).
3. Deploy the Edge Functions:
   ```bash
   supabase functions deploy request-otp
   supabase functions deploy verify-otp
   ```
4. You will need a [Resend](https://resend.com/) API key to send OTP emails. Add it as a secret to your Supabase project:
   ```bash
   supabase secrets set RESEND_API_KEY=your_resend_api_key_here
   ```

### 2. Client Setup
1. Open `Fortis.UI/Program.cs`.
2. Locate the Supabase Client registration and replace the placeholders with your actual Supabase URL and Anon Key:
   ```csharp
   appBuilder.Services.AddSingleton(new SupabaseClient(
       supabaseUrl: "YOUR_SUPABASE_URL",
       supabaseAnonKey: "YOUR_SUPABASE_ANON_KEY"
   ));
   ```

### 3. Running the App
Make sure you have the .NET 8 SDK installed.
```bash
cd Fortis.UI
dotnet run
```

Or publish it as a standalone executable:
```bash
dotnet publish -c Release
```
*(Note: If you publish the app, ensure the `wwwroot` folder remains in the same directory as your `.exe`)*

## Security Notice
This is a demonstration of a secure split-key architecture. In a true production environment, ensure that you set appropriate Row Level Security (RLS) policies on your Supabase tables so that authenticated users can only insert or interact with their own KeyShares.

## License
MIT
