using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            string cipherText = "";
            foreach(char letter in plainText)
            {
                // C = (index of P + key) mod 26
                // C: cipher text letter
                // P: plain text letter
                char A = char.IsUpper(letter) ? 'A' : 'a';
                char C = (char)(A + ((letter - A) + key) % 26);
                cipherText += C;
            }
            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            foreach(char letter in cipherText)
            {
                char A = char.IsUpper(letter) ? 'A' : 'a';
                char P = (char)(A + ((letter - A) + (26 - key)) % 26);
                plainText += P;
            }
            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            for(int key = 0; key < 26; key++)
            {
                string resultingCipherText = Encrypt(plainText, key);
                if (cipherText.Equals(resultingCipherText, StringComparison.InvariantCultureIgnoreCase))
                    return key;
            }
            return -1;
        }
    }
}
