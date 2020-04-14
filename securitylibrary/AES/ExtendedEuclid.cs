using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            List<int> T = new List<int>() {
                -1, 0, 0, 0,
            };
            // (A1, A2, A3) = (1, 0, baseN)
            List<int> A = new List<int>() {
                -1, 1, 0, baseN, 
            };
            // (B1, B2, B3) = (0, 1, number)
            List<int> B = new List<int>() {
                -1, 0, 1, number,
            };

            while (true)
            {
                if (B[3] == 0)
                    return -1;
                else if (B[3] == 1)
                    return ((B[2] % baseN) + baseN) % baseN;
                int Q = A[3] / B[3];
                // (T1,T2,T3) = (A1-QB1, A2-QB2, A3-QB3)
                T[1] = A[1] - (Q * B[1]);
                T[2] = A[2] - (Q * B[2]);
                T[3] = A[3] - (Q * B[3]);
                // (A1, A2, A3) = (B1, B2, B3)
                A[1] = B[1]; A[2] = B[2]; A[3] = B[3];
                // (B1, B2, B3) = (T1, T2, T3)
                B[1] = T[1]; B[2] = T[2]; B[3] = T[3];
            }
        }
    }
}
