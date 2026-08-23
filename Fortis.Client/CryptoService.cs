using System.Security.Cryptography;
using Konscious.Security.Cryptography;

namespace Fortis.Client;

public class CryptoService
{
    private const int KeySize = 32; // 256 bits
    private const int NonceSize = 12; // 96 bits for GCM
    private const int TagSize = 16; // 128 bits for GCM
    private const int SaltSize = 16;
    private const int ChunkSize = 1024 * 1024; // 1MB chunks

    /// <summary>
    /// Derives a 256-bit key from the password using Argon2id.
    /// </summary>
    public byte[] DeriveKeyFromPassword(string password, byte[] salt)
    {
        using var argon2 = new Argon2id(System.Text.Encoding.UTF8.GetBytes(password))
        {
            DegreeOfParallelism = 4,
            MemorySize = 65536, // 64 MB
            Iterations = 3,
            Salt = salt
        };

        return argon2.GetBytes(KeySize);
    }

    /// <summary>
    /// Securely generates a random Master Key and splits it into KeyShare_A and KeyShare_B.
    /// Returns (MasterKey, KeyShare_A, KeyShare_B).
    /// </summary>
    public (byte[] MasterKey, byte[] KeyShareA, byte[] KeyShareB) GenerateAndSplitKey(byte[] derivedPasswordKey)
    {
        byte[] masterKey = new byte[KeySize];
        byte[] keyShareA = new byte[KeySize];
        byte[] keyShareB = new byte[KeySize];

        RandomNumberGenerator.Fill(masterKey);
        RandomNumberGenerator.Fill(keyShareA);

        // KeyShare_B = MasterKey ^ DerivedPasswordKey ^ KeyShare_A
        for (int i = 0; i < KeySize; i++)
        {
            keyShareB[i] = (byte)(masterKey[i] ^ derivedPasswordKey[i] ^ keyShareA[i]);
        }

        return (masterKey, keyShareA, keyShareB);
    }

    /// <summary>
    /// Reconstructs the Master Key from the Password, KeyShare_A, and KeyShare_B.
    /// </summary>
    public byte[] ReconstructMasterKey(byte[] derivedPasswordKey, byte[] keyShareA, byte[] keyShareB)
    {
        byte[] masterKey = new byte[KeySize];

        // MasterKey = DerivedPasswordKey ^ KeyShare_A ^ KeyShare_B
        for (int i = 0; i < KeySize; i++)
        {
            masterKey[i] = (byte)(derivedPasswordKey[i] ^ keyShareA[i] ^ keyShareB[i]);
        }

        return masterKey;
    }

    /// <summary>
    /// Encrypts a file in chunks using AES-256-GCM.
    /// File Format: [Salt (16)] + chunks of [Nonce (12) + Ciphertext + Tag (16)]
    /// </summary>
    public void EncryptFile(string inputFilePath, string outputFilePath, byte[] masterKey, byte[] salt)
    {
        using var aes = new AesGcm(masterKey, TagSize);
        using var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

        // Write the Argon2 salt to the beginning of the file (in plaintext)
        outputStream.Write(salt);

        byte[] buffer = new byte[ChunkSize];
        int bytesRead;

        while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
        {
            byte[] nonce = new byte[NonceSize];
            RandomNumberGenerator.Fill(nonce);

            byte[] ciphertext = new byte[bytesRead];
            byte[] tag = new byte[TagSize];

            aes.Encrypt(nonce, buffer.AsSpan(0, bytesRead), ciphertext, tag);

            outputStream.Write(nonce);
            outputStream.Write(ciphertext);
            outputStream.Write(tag);
        }

        // Wipe sensitive buffer
        CryptographicOperations.ZeroMemory(buffer);
    }

    /// <summary>
    /// Decrypts a file in chunks using AES-256-GCM.
    /// </summary>
    public void DecryptFile(string inputFilePath, string outputFilePath, byte[] masterKey)
    {
        using var aes = new AesGcm(masterKey, TagSize);
        using var inputStream = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read);
        using var outputStream = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write);

        // Read the Argon2 salt (skip it here, caller extracts it first)
        byte[] salt = new byte[SaltSize];
        if (inputStream.Read(salt, 0, SaltSize) != SaltSize)
        {
            throw new InvalidOperationException("Invalid encrypted file format.");
        }

        // Each chunk on disk is: Nonce (12) + Ciphertext + Tag (16)
        // Ciphertext length is up to ChunkSize
        // So the max chunk size on disk is ChunkSize + NonceSize + TagSize
        byte[] nonce = new byte[NonceSize];
        byte[] tag = new byte[TagSize];
        byte[] ciphertextBuffer = new byte[ChunkSize];
        byte[] plaintextBuffer = new byte[ChunkSize];

        while (inputStream.Position < inputStream.Length)
        {
            int nonceBytesRead = inputStream.Read(nonce, 0, NonceSize);
            if (nonceBytesRead == 0) break; // EOF

            // We don't know the exact ciphertext length except by calculating remaining size,
            // but we know it's at most ChunkSize.
            long remainingBytes = inputStream.Length - inputStream.Position;
            long expectedChunkData = Math.Min(ChunkSize, remainingBytes - TagSize);

            int ciphertextBytesRead = inputStream.Read(ciphertextBuffer, 0, (int)expectedChunkData);
            int tagBytesRead = inputStream.Read(tag, 0, TagSize);

            if (tagBytesRead != TagSize)
            {
                throw new InvalidOperationException("Corrupted chunk data (missing tag).");
            }

            aes.Decrypt(nonce, ciphertextBuffer.AsSpan(0, ciphertextBytesRead), tag, plaintextBuffer.AsSpan(0, ciphertextBytesRead));

            outputStream.Write(plaintextBuffer, 0, ciphertextBytesRead);
        }

        // Wipe sensitive buffers
        CryptographicOperations.ZeroMemory(ciphertextBuffer);
        CryptographicOperations.ZeroMemory(plaintextBuffer);
    }

    /// <summary>
    /// Utility to securely wipe arrays from memory.
    /// </summary>
    public void SecureWipe(params byte[][] arrays)
    {
        foreach (var arr in arrays)
        {
            if (arr != null)
            {
                CryptographicOperations.ZeroMemory(arr);
            }
        }
    }
}
