using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public string Decrypt(string cipherText, List<string> key)
        {
            DES des = new DES();
            string DK0 = des.Decrypt(cipherText, key[0]);
            string EK1 = des.Encrypt(DK0, key[1]);
            return des.Decrypt(EK1, key[0]);
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES des = new DES();
            string EK0 = des.Encrypt(plainText, key[0]);
            string DK1 = des.Decrypt(EK0, key[1]);
            return des.Encrypt(DK1, key[0]);
        }

        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }

    }
}