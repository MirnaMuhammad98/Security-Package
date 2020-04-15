﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {
        public int numberRounds = 10;
        public int Nk  = 4;
        public int Nb = 4;

        // S-BOX shape: 16x16
        public static Byte[,] sbox = {
            { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
            { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
            { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
            { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
            { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
            { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
            { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
            { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
            { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
            { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
            { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
            { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
            { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
            { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
            { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
            { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }
        };
        // Inverse S-BOX shape: 16x16
        public static Byte[,] inv_sbox = {
            { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
            { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
            { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
            { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
            { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
            { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
            { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
            { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
            { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
            { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
            { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
            { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
            { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
            { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
            { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
            { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
        };

        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }

        public override string Encrypt(string plainText, string key)
        {
            // Convert plainText, key to ByteMatrixes
            List<List<Byte>> state = ToMatrix(plainText);
            List<Byte> w = new List<Byte>(4 * Nb * (numberRounds + 1)); //TODO: calculate the number of words in it
            // Elmfrod hna KeyExpansion bnndh 3liha b 2 list<Byte>
            KeyExpansion(ToMatrix(key), ref w);
            // AES Steps:
            /*
            1. Add round key [K0]
            2. Round Function (10 rounds for 128-bit key)
                2.1 Substitute bytes
                    2.1.1 Build the S-Box
                    2.1.2 Substitute
                2.2 Shift rows
                2.3 Mix columns
                2.4 Add round key [K1, K2 ... Kn]
                    2.4.1 Subkey generation
            */

            throw new NotImplementedException();
        }

        public List<List<Byte>> ToMatrix(string hexText)
        {
            List<List<Byte>> state = new List<List<Byte>>();
            if (hexText.Substring(0, 2) == "0x")
            {
                int j = 2; // skip 0x
                List<List<Byte>> temp = new List<List<Byte>>();
                for (int i = 0; i < 4; i++)
                {
                    List<Byte> row = new List<Byte>();
                    for (int k = 0; k < 4; k++)
                    {
                        string hexByte = "";
                        hexByte += hexText[j];
                        hexByte += hexText[j + 1];
                        Byte byteValue = Byte.Parse(hexByte, System.Globalization.NumberStyles.AllowHexSpecifier);
                        row.Add(byteValue);
                        j += 2;
                    }
                    temp.Add(row);
                }
                // The rows should be the columns
                // Transpose the temp
                for(int i = 0; i < 4; i++)
                {
                    List<Byte> row = new List<Byte>();
                    for(int k = 0; k < 4; k++)
                    {
                        row.Add(temp[k][i]);
                    }
                    state.Add(row);
                }
            }//else if text is in chars
            return state;
        }

        public void AddRoundKey(ref List<List<Byte>> box, List<Byte> key)
        {
            for(int i = 0; i < 4; i++)
            {
                for(int j = 0; j < Nb; j++)
                {
                    box[i][j] = (Byte)(box[i][j] ^ key[(j * 4) + i]);
                }
            }
        }

        public void RoundFunction(/*DS state, DS roundKey*/)
        {
            // Change void to return
            // the appropriate DS

            /*
            2. Round Function (10 rounds for 128-bit key)
                2.1 Substitute bytes
                    2.1.1 Build the S-Box
                    2.1.2 Substitute
                2.2 Shift rows
                2.3 Mix columns
                2.4 Add round key [K1, K2 ... Kn]
                    2.4.1 Subkey generation
            */
            throw new NotImplementedException();
        }

        public void SubBytes(ref List<List<Byte>> box)
        {
            for(int i = 0; i < 4; i++)
            {
                for(int j = 0; j < Nb; j++)
                {
                    box[i][j] = sbox[box[i][j] / 16, box[i][j] % 16];
                }
            }
        }

        public void InvSubBytes(ref List<List<Byte>> box)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < Nb; j++)
                {
                    box[i][j] = inv_sbox[box[i][j] / 16, box[i][j] % 16];
                }
            }
        }

        public void ShiftRow(ref List<List<Byte>> box, int row_index, int steps)
        {
            for(int i = 0; i < steps; i++)
            {
                byte tmp = box[row_index][0];
                for(int j = 0; j < Nb - 1; j++)
                {
                    box[row_index][j] = box[row_index][j + 1];
                }
                box[row_index][Nb - 1] = tmp;
            }
        }

        public void ShiftRows(ref List<List<Byte>> box)
        {
            ShiftRow(ref box, 1, 1);
            ShiftRow(ref box, 2, 2);
            ShiftRow(ref box, 3, 3);
        }

        public void InvShiftRows(ref List<List<Byte>> box)
        {
            ShiftRow(ref box, 1, Nb - 1);
            ShiftRow(ref box, 2, Nb - 2);
            ShiftRow(ref box, 3, Nb - 3);
        }

        public void MixColumns(ref List<List<Byte>> box)
        {
            for (int i = 0; i < Nb; i++)
            {
                box[i][0] = (Byte)(MulBytes((Byte)0x02, box[i][0]) ^ MulBytes((Byte)0x03, box[i][1]) ^ box[i][2] ^ box[i][3]);
                box[i][1] = (Byte)(box[i][0] ^ MulBytes((Byte)0x02, box[i][1]) ^ MulBytes((Byte)0x03, box[i][2]) ^ box[i][3]);
                box[i][2] = (Byte)(box[i][0] ^ box[i][1] ^ MulBytes((Byte)0x02, box[i][2]) ^ MulBytes((Byte)0x03, box[i][3]));
                box[i][3] = (Byte)(MulBytes((Byte)0x03, box[i][0]) ^ box[i][1] ^ box[i][2] ^ MulBytes((Byte)0x02, box[i][3]));
            }
        }

        public void InvMixColumns(ref List<List<Byte>> box)
        {
            for (int i = 0; i < Nb; i++)
            {
                box[i][0] = (Byte)(MulBytes((Byte)0x0e, box[i][0]) ^ MulBytes((Byte)0x0b, box[i][1]) ^ MulBytes((Byte)0x0d, box[i][2]) ^ MulBytes((Byte)0x09, box[i][3]));
                box[i][1] = (Byte)(MulBytes((Byte)0x09, box[i][0]) ^ MulBytes((Byte)0x0e, box[i][1]) ^ MulBytes((Byte)0x0b, box[i][2]) ^ MulBytes((Byte)0x0d, box[i][3]));
                box[i][2] = (Byte)(MulBytes((Byte)0x0d, box[i][0]) ^ MulBytes((Byte)0x09, box[i][1]) ^ MulBytes((Byte)0x0e, box[i][2]) ^ MulBytes((Byte)0x0b, box[i][3]));
                box[i][3] = (Byte)(MulBytes((Byte)0x0b, box[i][0]) ^ MulBytes((Byte)0x0d, box[i][1]) ^ MulBytes((Byte)0x09, box[i][2]) ^ MulBytes((Byte)0x0e, box[i][3]));
            }
        }

        public void KeyExpansion(List<Byte> key, ref List<Byte> w)
        {
            List<Byte> temp = new List<Byte> (4);
            List<Byte> rcon = new List<Byte>(4);
            
            for(int i = 0; i < 4 * Nk; i++)
            {
                w[i] = key[i];
            }

            for(int i = 4 * Nk; i < 4 * Nb *(numberRounds +  1); i += 4)
            {
                for (int j = 0; j < 4; j++)
                    temp[j] = w[i - 4 + j];

                if (i / (4 % Nk) == 0)
                {
                    RotWord(ref temp);
                    SubWord(ref temp);
                    Rcon(ref rcon, i / (Nk * 4));
                    XorWords(temp, rcon, ref temp);
                }
                else if (Nk > 6 && i / (4 % Nk) == 4)
                    SubWord(ref temp);

                for (int j = 0; j < 4; j++)
                    w[j + i] = (Byte)(w[i + j - 4 * Nk] ^ temp[j]);
            }
        }

        public Byte MulBytes(Byte b1, Byte b2)
        {
            Byte ans = 0;
            for(int i = 0; i < 8; i++)
            {
                if ((b2 & 1) == 1)
                {
                    Byte tmp = b1;
                    for (int j = 0; j < i; j++)
                        tmp = Xtime(tmp);
                    ans = (Byte)(ans ^ tmp);
                }
                b2 = (Byte)(b2 >> 1);
            }
            return ans;
        }

        public void RotWord(ref List<Byte> word)
        {
            Byte temp = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = temp;
        }

        public void SubWord(ref List<Byte> word)
        {
            for(int i = 0; i < 4; i++)
            {
                word[i] = sbox[word[i] / 16, word[i] % 16];
            }
        }

        public void XorWords(List<Byte> a, List<Byte> b, ref List<Byte> c)
        {
            for (int i = 0; i < 4; i++)
                c[i] = (Byte)(a[i] ^ b[i]);
        }

        // Round Constant
        public void Rcon(ref List<Byte> word, int n)
        {
            Byte c = 1;
            for(int i=0; i < n - 1; i++)
            {
                c = Xtime(c);
            }
            word[0] = c;
            word[1] = word[2] = word[3] = 0;
        }

        public Byte Xtime(Byte b)
        {
            Byte mask = 0x80, m = 0x1B;
            Byte highBit = (Byte)(b & mask);
            b <<= 1;
            if (highBit != 0x00)
            {
                b ^= m;
            }
            return b;
        }
    }
}
