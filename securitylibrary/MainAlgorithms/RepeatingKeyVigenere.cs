using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText  = plainText.ToLower();
            string key = "";
            for(int i = 0; i < plainText.Length; i++)
            {
                int shift_val = (cipherText[i] - plainText[i]);
                if (shift_val < 0) shift_val += 26;
                key += (char)('a' + shift_val);
            }

            string[] key_rep = new string[key.Length];
            for(int i = 0; i < key.Length; i++)
            {
                for( int j = i + 1; j < key.Length; j++)
                {
                    string s  = key.Substring(i, j - i + 1);
                    if (j + (j - i + 1) < key.Length)
                    {
                        string s1 = key.Substring(j + 1, j - i + 1);
                        if (s == s1)
                            return s;
                    }
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            int j = 0;
            string out_str = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (j == key.Length)
                    j = 0;
                int shift_val = (key[j] - 'a');
                int shifted_val = (cipherText[i] - shift_val);
                if (shifted_val < 97)
                    out_str += (char)('z' - ('a' - shifted_val - 1));
                else
                    out_str += (char)shifted_val;
                j++;
            }
            return out_str;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();
            int j = 0;
            string out_str = "";
            for(int i = 0; i < plainText.Length; i++)
            {
                if (j == key.Length)
                    j = 0;
                int shift_val   = (key[j] - 'a');
                int shifted_val = (plainText[i] + shift_val);
                if (shifted_val > 122)
                    out_str += (char)('a' + (shifted_val - 123));
                else
                    out_str += (char)shifted_val;
                j++;
            }
            return out_str;
        }
    }
}