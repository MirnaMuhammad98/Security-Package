using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES {
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique {
        struct Halves {
            public ulong Left;
            public ulong Right;
        }

        ulong[] keys = new ulong[16]; // Array to hold all the keys that will be generated
        bool keysGenerated = false;

        public override string Decrypt(string cipherText, string key) {
            ulong plainBlock = Convert.ToUInt64(cipherText, 16); // Convert Hex string to 64 bits number
            ulong plainKey = Convert.ToUInt64(key, 16);

            if (!keysGenerated) {
                GenerateKeys(plainKey);
                keysGenerated = true;
            }

            ulong initialPermBlock = Permute(plainBlock, ref initialPermTable);
            Halves halves = Split64(initialPermBlock);
            for (int i = 0; i < 16; i++) {
                halves = Round(halves, keys[15 - i]);
            }

            ulong swapped = halves.Right | (halves.Left >> 32);
            ulong final = Permute(swapped, ref inverseInitialPermTable);

            return "0x" + final.ToString("X").PadLeft(16, '0');
        }
        
        public override string Encrypt(string plainText, string key) {

            ulong plainBlock = Convert.ToUInt64(plainText, 16); // Convert Hex string to 64 bits number
            ulong plainKey = Convert.ToUInt64(key, 16);

            if (!keysGenerated) {
                GenerateKeys(plainKey);
                keysGenerated = true;
            }

            ulong initialPermBlock = Permute(plainBlock, ref initialPermTable);
            Halves halves = Split64(initialPermBlock);
            for(int i = 0; i < 16; i++) {
                halves = Round(halves, keys[i]);
            }

            ulong swapped = halves.Right | (halves.Left >> 32);
            ulong final = Permute(swapped, ref inverseInitialPermTable);

            return "0x" + final.ToString("X").PadLeft(16, '0');
        }

        // Takes original key and generates all 16 keys.
        void GenerateKeys(ulong key) {
            ulong pc1Key = Permute(key, ref permChoice1Table);
            Halves keyHalves = Split56(pc1Key);
            for (int i = 0; i < 16; i++) {
                keyHalves.Left = LeftShift56(keyHalves.Left, LeftShifts[i]);
                keyHalves.Right = LeftShift56(keyHalves.Right, LeftShifts[i]);
                ulong newKey = Merge(keyHalves);
                keys[i] = Permute(newKey, ref permChoice2Table);
            }
        }

        ulong Permute(ulong block, ref int[] permTable) {
            ulong permutedBlock = 0;
            int blockSize = 64;
            for (int i = 0; i < permTable.Length; i++) {
                int pos = permTable[i];
                ulong bit = (block >> (blockSize - pos)) & 1;
                permutedBlock |= bit << (blockSize - 1 - i);
            }
            return permutedBlock;
        }

        Halves Split56(ulong block) {
            Halves splitBlock = new Halves();
            splitBlock.Left = block >> (64 - 28) << (64 - 28);
            splitBlock.Right = block << 28;
            return splitBlock;
        }

        ulong LeftShift56(ulong val, int shiftLength) {
            for (int i = 0; i < shiftLength; i++) {
                ulong msb = val & 0x8000000000000000;
                val = ((val << 1) & 0xFFFFFFE000000000) | (msb >> 27);
            }
            return val;
        }

        ulong Merge(Halves halves) {
            return (halves.Left & 0xFFFFFFF000000000) | ((halves.Right & 0xFFFFFFF000000000) >> 28);
        }

        Halves Split64(ulong block) {
            Halves splitBlock = new Halves();
            splitBlock.Left = block >> 32 << 32;
            splitBlock.Right = block << 32;
            return splitBlock;
        }

        Halves Round(Halves block, ulong key) {
            ulong expandedRightHalf = Permute(block.Right, ref expansionTable);
            ulong nextRight = expandedRightHalf ^ key;
            byte[] sboxesInput = SplitIntoEight(nextRight); // split 48 bits into 8 groups of 6-bits
            ulong sBoxesRes = 0;
            for(int i = 0; i < 8; i++) {
                sBoxesRes <<= 4;
                sBoxesRes |= FromSBox(sboxesInput[i], i);
            }
            sBoxesRes <<= 32;
            nextRight = Permute(sBoxesRes, ref permutationTable);
            nextRight ^= block.Left;
            ulong nextLeft = block.Right;
            return new Halves { Left = nextLeft, Right = nextRight };
        }

        // Split 48-bit block into eight 6-bit values (left-aligned in a byte)
        byte[] SplitIntoEight(ulong block) {
            byte[] bytes = new byte[8];
            for (int i = 0; i < 8; i++) {
                bytes[i] = (byte)((block & 0xFC00000000000000) >> 56);
                block <<= 6;
            }
            return bytes;
        }

        byte FromSBox(byte sixBit, int sBoxIndex) {
            int row = ((sixBit & 0b00000100) >> 2) | ((sixBit & 0b10000000) >> 6);
            int col = (sixBit & 0b01111000) >> 3;
            return (byte)(SBoxes[sBoxIndex][row, col]);
        }

        #region DES Tables

        int[] initialPermTable = new int[64] {
            58,50,42,34,26,18,10,2,
            60,52,44,36,28,20,12,4,
            62,54,46,38,30,22,14,6,
            64,56,48,40,32,24,16,8,
            57,49,41,33,25,17,9,1,
            59,51,43,35,27,19,11,3,
            61,53,45,37,29,21,13,5,
            63,55,47,39,31,23,15,7
        };

        int[] inverseInitialPermTable = new int[64] {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41,  9, 49, 17, 57, 25,
        };

        #region Key Tables

        int[] permChoice1Table = new int[56] {
            57,49,41,33,25,17,9,
            1,58,50,42,34,26,18,
            10,2,59,51,43,35,27,
            19,11,3,60,52,44,36,
            63,55,47,39,31,23,15,
            7,62,54,46,38,30,22,
            14,6,61,53,45,37,29,
            21,13,5,28,20,12,4
        };

        int[] permChoice2Table = new int[48] {
            14,17,11,24,1,5,
            3,28,15,6,21,10,
            23,19,12,4,26,8,
            16,7,27,20,13,2,
            41,52,31,37,47,55,
            30,40,51,45,33,48,
            44,49,39,56,34,53,
            46,42,50,36,29,32
        };

        int[] LeftShifts = new int[16] { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

        #endregion

        #region Round Tables

        int[] expansionTable = new int[48] {
            32,1,2,3,4,5,4,5,
          6,7,8,9,8,9,10,11,
          12,13,12,13,14,15,16,17,
          16,17,18,19,20,21,20,21,
          22,23,24,25,24,25,26,27,
          28,29,28,29,30,31,32,1
        };

        int[] permutationTable = new int[32] {
            16,7,20,21,29,12,28,17,
            1,15,23,26,5,18,31,10,
            2,8,24,14,32,27,3,9,
            19,13,30,6,22,11,4,25
        };

        int[][,] SBoxes = { // Array of 2D Arrays
            new int[,] {
                {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
                {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
                {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
                {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
            },
            new int[,] {
                { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
                {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
                {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
                {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
            },
            new int[,] {
                { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
                {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
            },
            new int[,] {
                { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
                {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
            },
            new int[,] {
                {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
                {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
                {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
                {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
            },
            new int[,] {
                {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
                {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
                {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
                {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
            },
            new int[,] {
                {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
                {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
                {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
                {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
            },
            new int[,] {
                {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
                {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
                {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
                {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
            }
        };

        #endregion

        #endregion

    }
}