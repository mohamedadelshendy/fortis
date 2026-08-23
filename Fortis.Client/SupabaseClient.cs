using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Fortis.Client;

public class SupabaseClient
{
    private readonly HttpClient _httpClient;
    private readonly string _supabaseUrl;
    private readonly string _supabaseAnonKey;

    public SupabaseClient(string supabaseUrl, string supabaseAnonKey)
    {
        _supabaseUrl = supabaseUrl;
        _supabaseAnonKey = supabaseAnonKey;
        
        _httpClient = new HttpClient();
        _httpClient.DefaultRequestHeaders.Add("apikey", _supabaseAnonKey);
        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_supabaseAnonKey}");
    }

    /// <summary>
    /// Stores KeyShare_B in the database upon initial encryption.
    /// Uses PostgREST endpoint for `encrypted_files`.
    /// Note: The RLS policy in Step 1 was set to block all client inserts by default. 
    /// To make this work, either an Edge Function must handle the initial upload OR 
    /// an authenticated user RLS policy is required for insertion. 
    /// Assuming we add an Edge Function or RLS policy for insert later.
    /// </summary>
    public async Task<string> StoreFileMetadataAsync(string userEmail, byte[] keyShareB)
    {
        string base64KeyShareB = Convert.ToBase64String(keyShareB);
        
        var payload = new
        {
            user_email = userEmail,
            key_share_b = base64KeyShareB
        };

        var response = await _httpClient.PostAsJsonAsync($"{_supabaseUrl}/rest/v1/encrypted_files", payload);
        response.EnsureSuccessStatusCode();

        // Parse returned ID (assuming Prefer: return=representation header was used, or we just generate ID locally)
        // For simplicity, we can generate a UUID locally and send it, or read the response.
        // Let's assume we generated it locally and inserted it.
        return "Requires Insert Implementation depending on final RLS / Edge Function choice";
    }

    /// <summary>
    /// Calls the request-otp Edge Function.
    /// </summary>
    public async Task RequestOtpAsync(string fileId, string email)
    {
        var payload = new { file_id = fileId, email = email };
        var response = await _httpClient.PostAsJsonAsync($"{_supabaseUrl}/functions/v1/request-otp", payload);
        
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync();
            throw new Exception($"Failed to request OTP: {error}");
        }
    }

    /// <summary>
    /// Calls the verify-otp Edge Function. Returns KeyShare_B if successful.
    /// </summary>
    public async Task<byte[]> VerifyOtpAsync(string fileId, string otp)
    {
        var payload = new { file_id = fileId, otp = otp };
        var response = await _httpClient.PostAsJsonAsync($"{_supabaseUrl}/functions/v1/verify-otp", payload);
        
        if (!response.IsSuccessStatusCode)
        {
            var error = await response.Content.ReadAsStringAsync();
            throw new Exception($"Failed to verify OTP: {error}");
        }

        var result = await response.Content.ReadFromJsonAsync<VerifyOtpResponse>();
        if (result?.key_share_b == null)
        {
            throw new Exception("Invalid response from verify-otp.");
        }

        return Convert.FromBase64String(result.key_share_b);
    }
    
    private class VerifyOtpResponse
    {
        public string? key_share_b { get; set; }
    }
}
