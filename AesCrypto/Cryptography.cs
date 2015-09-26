using System;
using System.IO;
using System.Security.Cryptography;

namespace AesCrypto
{
    public static class Cryptography
    {
        /// <summary>
        /// Encrypts string to an array of bytes using an AesCryptoServiceProvider.
        /// </summary>
        /// <param name="plainText">Input value to be necrypted.</param>
        /// <param name="Key">Key used in the encryption process.</param>
        /// <returns>An ecnrypted byte array.</returns>
        public static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key)
        {
            // Check arguments.
            if (string.IsNullOrWhiteSpace(plainText))
            {
                throw new ArgumentNullException("plainText");
            }
            if (Key == null || Key.Length <= 0)
            {
                throw new ArgumentNullException("Key");
            }

            // Byte array used to store the encrypted data.
            byte[] encrypted;

            // Create an AesCryptoServiceProvider object with the specified key and
            // a random IV.
            using (var aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = Key;
                aesAlg.GenerateIV();

                // Create a decrytor to perform the stream transform.
                using (var encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))
                {
                    // Create the streams used for encryption.
                    using (var msEncrypt = new MemoryStream())
                    {
                        // Write out IV.
                        msEncrypt.Write(aesAlg.IV, 0, 16);

                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        {
                            using (var swEncrypt = new StreamWriter(csEncrypt))
                            {
                                //Write all data to the stream.
                                swEncrypt.Write(plainText);
                            }
                            encrypted = msEncrypt.ToArray();
                        }
                    }
                }
            }
            return encrypted;
        }

        /// <summary>
        /// Decrypts a byte array using an AesCryptoServiceProvider.
        /// </summary>
        /// <param name="cipherText">An encrypted array of bytes.</param>
        /// <param name="Key">Key used in the original encryption process.</param>
        /// <returns>A decrypted string.</returns>
        public static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
            {
                throw new ArgumentNullException("cipherText");
            }
            if (Key == null || Key.Length <= 0)
            {
                throw new ArgumentNullException("Key");
            }

            // Declare the string used to hold the decrypted text.
            string plaintext = null;

            // Create an AesCryptoServiceProvider object with the specified key.
            using (var aesAlg = new AesCryptoServiceProvider())
            {
                aesAlg.Key = Key;

                // Create the stream used for decryption.
                using (var msDecrypt = new MemoryStream(cipherText))
                {
                    // Read in IV.
                    var buffer = new byte[16];
                    msDecrypt.Read(buffer, 0, 16);
                    aesAlg.IV = buffer;

                    // Create a decrytor to perform the stream transform.
                    using (var decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                // Read the decrypted bytes from the decrypting stream 
                                // and place them in a string.
                                plaintext = srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }
            }
            return plaintext;
        }
    }
}
