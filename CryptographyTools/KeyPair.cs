using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptographyTools
{
    public class KeyPair
    {
        public string PublicKey { get; set; }

        public string PrivateKey { get; set; }

        public KeyPair(string publicKey, string privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }
    }
}
