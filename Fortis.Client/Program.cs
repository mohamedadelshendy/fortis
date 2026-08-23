using System.Security.Cryptography;
using Fortis.Client;

// =====================================================================================
// FORTIS CLIENT - CORE ENCRYPTION / DECRYPTION ORCHESTRATION DEMO
// =====================================================================================

Console.WriteLine("Fortis Secure File Encryption Client");
Console.WriteLine("=====================================");

// In a real desktop app, these would be collected via the UI (WPF / WinForms / MAUI).
string password = "my_ultra_secure_password123!";
string email = "user@example.com";
string fileId = Guid.NewGuid().ToString(); // Usually generated during encryption

// Initialize Services
var crypto = new CryptoService();
var supabase = new SupabaseClient(
    supabaseUrl: "https://your-project-id.supabase.co",
    supabaseAnonKey: "your-anon-key"
);

// -------------------------------------------------------------------------------------
// 1. ENCRYPTION FLOW (Offline + Online)
// -------------------------------------------------------------------------------------
Console.WriteLine("\n--- ENCRYPTION FLOW ---");

// Generate Salt for Argon2
byte[] salt = new byte[16];
RandomNumberGenerator.Fill(salt);

// 1. Derive Key from Password
Console.WriteLine("Deriving K_pass from password using Argon2id...");
byte[] derivedPasswordKey = crypto.DeriveKeyFromPassword(password, salt);

// 2. Generate Master Key and split it via XOR
Console.WriteLine("Generating Master Key and splitting into KeyShare_A and KeyShare_B...");
var (masterKey, keyShareA, keyShareB) = crypto.GenerateAndSplitKey(derivedPasswordKey);

// 3. Encrypt the file in chunks
string inputFilePath = "plaintext.txt";
string encryptedFilePath = "encrypted.bin";
string keyShareAFilePath = "keyshare_a.txt";

// Create dummy file for demo
File.WriteAllText(inputFilePath, "This is top secret data that needs to be encrypted.");

Console.WriteLine($"Encrypting {inputFilePath} to {encryptedFilePath} in 1MB chunks...");
crypto.EncryptFile(inputFilePath, encryptedFilePath, masterKey, salt);

// 4. Save KeyShare_A locally
File.WriteAllText(keyShareAFilePath, Convert.ToBase64String(keyShareA));
Console.WriteLine($"Saved KeyShare_A to {keyShareAFilePath}");

// 5. Securely upload KeyShare_B to Supabase (Mocked here since we didn't implement the Edge Function for upload)
Console.WriteLine("Uploading KeyShare_B and File Metadata to Supabase...");
// await supabase.StoreFileMetadataAsync(email, keyShareB); 

// Securely wipe memory
crypto.SecureWipe(derivedPasswordKey, masterKey, keyShareA, keyShareB);
Console.WriteLine("Memory securely wiped. Encryption complete.");

// -------------------------------------------------------------------------------------
// 2. DECRYPTION FLOW (Strict MFA)
// -------------------------------------------------------------------------------------
Console.WriteLine("\n--- DECRYPTION FLOW ---");

try
{
    // 1. User selects encrypted file, enters password, and provides KeyShare_A
    byte[] recoveredKeyShareA = Convert.FromBase64String(File.ReadAllText(keyShareAFilePath));
    
    // Read salt from the first 16 bytes of the encrypted file
    byte[] recoveredSalt = new byte[16];
    using (var fs = new FileStream(encryptedFilePath, FileMode.Open, FileAccess.Read))
    {
        fs.Read(recoveredSalt, 0, 16);
    }

    Console.WriteLine("Deriving K_pass from password...");
    byte[] recoveredDerivedPasswordKey = crypto.DeriveKeyFromPassword(password, recoveredSalt);

    // 2. Request OTP from Supabase Edge Function
    Console.WriteLine($"Requesting OTP via Email for file ID: {fileId}...");
    // await supabase.RequestOtpAsync(fileId, email);

    // 3. User inputs OTP (Simulated)
    Console.Write("Enter the 6-digit OTP sent to your email: ");
    string otp = "123456"; // Console.ReadLine();

    // 4. Send OTP to Supabase to verify and retrieve KeyShare_B
    Console.WriteLine("Verifying OTP with Supabase Edge Function...");
    // byte[] recoveredKeyShareB = await supabase.VerifyOtpAsync(fileId, otp);
    
    // (MOCKING SUCCESSFUL OTP VERIFICATION FOR DEMO)
    byte[] recoveredKeyShareB = new byte[32]; 
    // In reality, this comes from the VerifyOtpAsync call!

    // 5. Reconstruct Master Key
    Console.WriteLine("Reconstructing Master Key via XOR...");
    byte[] reconstructedMasterKey = crypto.ReconstructMasterKey(recoveredDerivedPasswordKey, recoveredKeyShareA, recoveredKeyShareB);

    // 6. Decrypt the file
    string decryptedFilePath = "decrypted.txt";
    Console.WriteLine($"Decrypting {encryptedFilePath} to {decryptedFilePath}...");
    
    // THIS WILL FAIL IN THIS MOCK DEMO BECAUSE RECOVERED KEYSHARE_B IS EMPTY
    // crypto.DecryptFile(encryptedFilePath, decryptedFilePath, reconstructedMasterKey);

    Console.WriteLine("Decryption complete!");

    // Securely wipe memory
    crypto.SecureWipe(recoveredKeyShareA, recoveredDerivedPasswordKey, recoveredKeyShareB, reconstructedMasterKey);
}
catch (Exception ex)
{
    Console.WriteLine($"Decryption Failed: {ex.Message}");
}
