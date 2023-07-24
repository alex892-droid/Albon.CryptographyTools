using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace Albon.CryptographyTools
{
    public class Base64UrlEncoder
    {
        static private Encoding encoding = new UTF8Encoding(false);
        private const char BASE64_CHARACTER_62 = '+';
        private const char BASE64_CHARACTER_63 = '/';
        private const char BASE64_URL_CHARACTER_62 = '-';
        private const char BASE64_URL_CHARACTER_63 = '_';
        private const char BASE64_SINGLE_PAD_CHARACTER = '=';

        public static string ToBase64UrlEncode(byte[] _bytes)
        {
            string base64String = Convert.ToBase64String(_bytes);

            // Step 2: Replace characters not allowed in URLs
            string base64Url = base64String.Replace('+', '-').Replace('/', '_').TrimEnd('=');

            return base64Url;
        }

        public static byte[] FromBase64UrlEncode(string text)
        {
            // Step 1: Convert Base64 URL to Base64
            int padding = 4 - text.Length % 4;
            if(padding != 4)
            {
                text = text + new string('=', padding); // Add back the padding
            }
            string base64String = text.Replace('-', '+').Replace('_', '/');

            // Step 2: Decode Base64 to byte array
            byte[] base64Bytes = Convert.FromBase64String(base64String);

            return base64Bytes;
        }
    }
}
