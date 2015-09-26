using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AesCrypto
{
    class Program
    {
        static void Main(string[] args)
        {
            var msg = "This is a secret message.";

            var key = new byte[] { 255, 3, 45, 122, 
                                   55, 213, 144, 55, 
                                   89, 144, 67, 244,
                                   14, 234, 251, 111 };

            var encrypted = Cryptography.EncryptStringToBytes_Aes(msg, key);
            var decrypted = Cryptography.DecryptStringFromBytes_Aes(encrypted, key);

            Console.WriteLine("Original string: {0}", msg);
            Console.WriteLine("Encrypted string: {0}", Encoding.Default.GetString(encrypted));
            Console.WriteLine("Decrypted string: {0}", decrypted);
        }
    }
}
