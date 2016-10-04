using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace WpfDemo
{
    public class SerpentStandardMode : SerpentAlgorithm
    {
        // Constants and variables
        //...........................................................................

        public override int BlockSize { get; set; } // bytes in a data-block
        public override int Rounds { get; set; } // number of rounds

        #region Basic API Methods
        // Basic API methods
        //...........................................................................

        /// <summary>
        /// Expand a user-supplied key material into a session key.
        /// </summary>
        /// <param name="key">The user-key bytes (multiples of 4) to use.</param>
        /// <returns></returns>
        public override object MakeKey(byte[] key)
        {
            // compute prekeys w[]:
            // (a) from user key material
            int[] w = new int[4 * (Rounds + 1)];
            int offset = 0;
            int limit = key.Length / 4;
            int i, j;
            for (i = 0; i < limit; i++)
                w[i] = (key[offset++] & 0xFF) |
                       (key[offset++] & 0xFF) << 8 |
                       (key[offset++] & 0xFF) << 16 |
                       (key[offset++] & 0xFF) << 24;

            if (i < 8)
                w[i++] = 1;

            // (b) and expanding them to full 132 x 32-bit material
            // this is a literal implementation of the Serpent paper
            // (section 4 The Key Schedule, p.226)
            int t;
            // start by computing the first 8 values using the second
            // lot of 8 values as an intermediary buffer
            for (i = 8, j = 0; i < 16; i++)
            {
                t = (int)(w[j] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ j++);
                w[i] = t << 11 | (int)((uint)t >> 21);
            }
            // translate the buffer by -8
            for (i = 0, j = 8; i < 8; )
                w[i++] = w[j++];
            limit = 4 * (Rounds + 1); // 132 for a 32-round Serpent
            // finish computing the remaining intermediary subkeys
            for (; i < limit; i++)
            {
                t = (int)(w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ i);
                w[i] = t << 11 | (int)((uint)t >> 21);
            }

            // compute intermediary key into k[]
            int[] k = new int[limit];
            int box, a, b, c, d, inV, outV;
            for (i = 0; i < Rounds + 1; i++)
            {
                box = (Rounds + 3 - i) % Rounds;
                a = w[4 * i];
                b = w[4 * i + 1];
                c = w[4 * i + 2];
                d = w[4 * i + 3];

                for (j = 0; j < 32; j++)
                {
                    inV = GetBit(a, j) |
                          GetBit(b, j) << 1 |
                          GetBit(c, j) << 2 |
                          GetBit(d, j) << 3;
                    outV = S(box, inV);
                    k[4 * i] |= GetBit(outV, 0) << j;
                    k[4 * i + 1] |= GetBit(outV, 1) << j;
                    k[4 * i + 2] |= GetBit(outV, 2) << j;
                    k[4 * i + 3] |= GetBit(outV, 3) << j;
                }
            }
            // renumber the 32-bit values k[] as 128-bit subkeys K[][]
            int[][] K = new int[Rounds + 1][]; // [4] nie mogę zadeklarować w ten sposób w c#
            for (int kn = 0; kn < K.Length; kn++)
                K[kn] = new int[4];

            for (i = 0, offset = 0; i < Rounds + 1; i++)
            {
                K[i][0] = k[offset++];
                K[i][1] = k[offset++];
                K[i][2] = k[offset++];
                K[i][3] = k[offset++];
            }
            // we now apply IP to the round key in order to place the key bits
            // in the correct column; ie. Khat[i] = IP(K[i]) --we use same K
            for (i = 0; i < Rounds + 1; i++)
                K[i] = IP(K[i]);

            return K;
        }

        /// <summary>
        /// Encrypt exactly one block of plaintext.
        /// </summary>
        /// <param name="inV">The plaintext.</param>
        /// <param name="inOffset">Index of in from which to start considering data.</param>
        /// <param name="sessionKey">The session key to use for encryption.</param>
        /// <returns>The ciphertext generated from a plaintext using the session key.</returns>
        public override byte[] BlockEncrypt(byte[] inV, int inOffset, object sessionKey)
        {
            int[][] Khat = (int[][])sessionKey;
            int[] x = {
                (inV[inOffset++] & 0xFF)       | (inV[inOffset++] & 0xFF) <<  8 |
                (inV[inOffset++] & 0xFF) << 16 | (inV[inOffset++] & 0xFF) << 24,
                (inV[inOffset++] & 0xFF)       | (inV[inOffset++] & 0xFF) <<  8 |
                (inV[inOffset++] & 0xFF) << 16 | (inV[inOffset++] & 0xFF) << 24,
                (inV[inOffset++] & 0xFF)       | (inV[inOffset++] & 0xFF) <<  8 |
                (inV[inOffset++] & 0xFF) << 16 | (inV[inOffset++] & 0xFF) << 24,
                (inV[inOffset++] & 0xFF)       | (inV[inOffset++] & 0xFF) <<  8 |
                (inV[inOffset++] & 0xFF) << 16 | (inV[inOffset++] & 0xFF) << 24
            };
            int[] Bhat = IP(x);

            for (int i = 0; i < Rounds; i++)
                Bhat = R(i, Bhat, Khat);

            x = FP(Bhat);

            int a = x[0], b = x[1], c = x[2], d = x[3];
            byte[] result = new byte[] {
                (byte)(a), (byte)((int)((uint)a >> 8)), (byte)((int)((uint)a >> 16)), (byte)((int)((uint)a >> 24)),
                (byte)(b), (byte)((int)((uint)b >> 8)), (byte)((int)((uint)b >> 16)), (byte)((int)((uint)b >> 24)),
                (byte)(c), (byte)((int)((uint)c >> 8)), (byte)((int)((uint)c >> 16)), (byte)((int)((uint)c >> 24)),
                (byte)(d), (byte)((int)((uint)d >> 8)), (byte)((int)((uint)d >> 16)), (byte)((int)((uint)d >> 24))
            };
            return result;
        }

        /// <summary>
        /// Decrypt exactly one block of ciphertext.
        /// </summary>
        /// <param name="inV">The ciphertext.</param>
        /// <param name="inOffset">Index of in from which to start considering data.</param>
        /// <param name="sessionKey">The session key to use for decryption.</param>
        /// <returns>The plaintext generated from a ciphertext using the session key.</returns>
        public override byte[] BlockDecrypt(byte[] inV, int inOffset, object sessionKey)
        {
            int[][] Khat = (int[][])sessionKey;
            int[] x = {
                (inV[inOffset++] & 0xFF)       | (inV[inOffset++] & 0xFF) <<  8 |
                (inV[inOffset++] & 0xFF) << 16 | (inV[inOffset++] & 0xFF) << 24,
                (inV[inOffset++] & 0xFF)       | (inV[inOffset++] & 0xFF) <<  8 |
                (inV[inOffset++] & 0xFF) << 16 | (inV[inOffset++] & 0xFF) << 24,
                (inV[inOffset++] & 0xFF)       | (inV[inOffset++] & 0xFF) <<  8 |
                (inV[inOffset++] & 0xFF) << 16 | (inV[inOffset++] & 0xFF) << 24,
                (inV[inOffset++] & 0xFF)       | (inV[inOffset++] & 0xFF) <<  8 |
                (inV[inOffset++] & 0xFF) << 16 | (inV[inOffset++] & 0xFF) << 24
            };
            int[] Bhat = FPinverse(x);

            for (int i = Rounds - 1; i >= 0; i--)
                Bhat = Rinverse(i, Bhat, Khat);

            x = IPinverse(Bhat);

            int a = x[0], b = x[1], c = x[2], d = x[3];
            byte[] result = new byte[] {
                (byte)(a), (byte)((int)((uint)a >> 8)), (byte)((int)((uint)a >> 16)), (byte)((int)((uint)a >> 24)),
                (byte)(b), (byte)((int)((uint)b >> 8)), (byte)((int)((uint)b >> 16)), (byte)((int)((uint)b >> 24)),
                (byte)(c), (byte)((int)((uint)c >> 8)), (byte)((int)((uint)c >> 16)), (byte)((int)((uint)c >> 24)),
                (byte)(d), (byte)((int)((uint)d >> 8)), (byte)((int)((uint)d >> 16)), (byte)((int)((uint)d >> 24))
            };

            return result;
        }

        public byte[] BlockDecryptGetP(int inV, int val, int inOffset, object sessionKey)
        {
            int[][] Khat = (int[][])sessionKey;
            int[] x = { 0, 0, 0, 0 };
            int[] Bhat = FPinverse(x);
            for (int i = Rounds - 1; i >= 0; i--)
                Bhat = Rinverse(i, Bhat, Khat, inV, val);
            x = IPinverse(Bhat);

            int a = x[0], b = x[1], c = x[2], d = x[3];
            byte[] result = new byte[] {
                (byte)(a), (byte)((int)((uint)a >> 8)), (byte)((int)((uint)a >> 16)), (byte)((int)((uint)a >> 24)),
                (byte)(b), (byte)((int)((uint)b >> 8)), (byte)((int)((uint)b >> 16)), (byte)((int)((uint)b >> 24)),
                (byte)(c), (byte)((int)((uint)c >> 8)), (byte)((int)((uint)c >> 16)), (byte)((int)((uint)c >> 24)),
                (byte)(d), (byte)((int)((uint)d >> 8)), (byte)((int)((uint)d >> 16)), (byte)((int)((uint)d >> 24))
            };

            return result;
        }
        #endregion

        #region Own Methods
        // own methods
        //...........................................................................

        /// <returns>
        ///     The bit value at position <code>i</code> in a 32-bit entity,
        ///     where the least significant bit (the rightmost one) is at
        ///     position 0.
        /// </returns>
        private int GetBit(int x, int i)
        {
            return ((int)((uint)x >> i)) & 0x01;
        }

        /// <returns>
        ///     The bit value at position <code>i</code> in an array of 32-bit
        ///     entities, where the least significant 32-bit entity is at index
        ///     position 0 and the least significant bit (the rightmost one) in
        ///     any 32-bit entity is at position 0.
        /// </returns>
        private int GetBit(int[] x, int i)
        {
            return ((int)((uint)x[i / 32] >> (i % 32))) & 0x01;
        }

        /*
            Set the bit at position <code>i</code> in an array of 32-bit entities
            to a given value <code>v</code>, where the least significant 32-bit
            entity is at index position 0 and the least significant bit (the
            rightmost one) in any 32-bit entity is at position 0.
        */

        /// <summary>
        /// Set the bit at position <code>i</code> in an array of 32-bit entities
        /// to a given value <code>v</code>, where the least significant 32-bit
        /// entity is at index position 0 and the least significant bit (the
        /// rightmost one) in any 32-bit entity is at position 0.
        /// </summary>
        private void SetBit(int[] x, int i, int v)
        {
            if ((v & 0x01) == 1)
                x[i / 32] |= 1 << (i % 32); // set it
            else
                x[i / 32] &= ~(1 << (i % 32)); // clear it
        }

        /// <returns>
        ///     The nibble --a 4-bit entity-- in <code>x</code> given its
        ///     position <code>i</code>, where the least significant nibble
        ///     (the rightmost one) is at position 0.
        /// </returns>
        private static int GetNibble(int x, int i)
        {
            return ((int)((uint)x >> (4 * i))) & 0x0F;
        }

        /// <returns>
        ///     A 128-bit entity which is the result of applying the Initial
        ///     Permutation (IP) to a 128-bit entity <code>x</code>.
        /// </returns>
        private int[] IP(int[] x)
        {
            return Permutate(IPtable, x);
        }

        /// <returns>
        ///     A 128-bit entity which is the result of applying the inverse of
        ///     the Initial Permutation to a 128-bit entity <code>x</code>.
        /// </returns>
        private int[] IPinverse(int[] x)
        {
            return Permutate(FPtable, x);
        }

        /// <returns>
        ///     A 128-bit entity which is the result of applying the Final
        ///     Permutation (FP) to a 128-bit entity <code>x</code>.
        /// </returns>
        private int[] FP(int[] x)
        {
            return Permutate(FPtable, x);
        }

        /// <returns>
        ///     A 128-bit entity which is the result of applying the inverse of
        ///     the Final Permutation to a 128-bit entity <code>x</code>.
        /// </returns>
        private int[] FPinverse(int[] x)
        {
            return Permutate(IPtable, x);
        }

        /// <returns>
        ///     A 128-bit entity which is the result of applying a permutation
        ///     coded in a given table <code>T</code> to a 128-bit entity <code>x</code>.
        /// </returns>
        private int[] Permutate(byte[] T, int[] x)
        {
            int[] result = new int[4];
            for (int i = 0; i < 128; i++)
                SetBit(result, i, GetBit(x, T[i] & 0x7F));
            return result;
        }

        /// <returns>
        ///     A 128-bit entity as the result of XORing, bit-by-bit, two given
        ///     128-bit entities <code>x</code> and <code>y</code>.
        /// </returns>
        private int[] xor128(int[] x, int[] y)
        {
            return new int[] { x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3] };
        }

        /// <returns>
        ///     The nibble --a 4-bit entity-- obtained by applying a given
        ///     S-box to a 32-bit entity <code>x</code>.
        /// </returns>
        private int S(int box, int x)
        {
            return Sbox[box % 32][x] & 0x0F;
        }

        /// <returns>
        ///     The nibble --a 4-bit entity-- obtained byapplying the inverse
        ///     of a given S-box to a 32-bit entity <code>x</code>.
        /// </returns>
        private int Sinverse(int box, int x)
        {
            return SboxInverse[box % 32][x] & 0x0F;
        }

        /// <returns>            
        ///     @return A 128-bit entity being the result of applying, in parallel,
        ///     32 copies of a given S-box to a 128-bit entity <code>x</code>.
        /// </returns>
        private int[] Shat(int box, int[] x)
        {
            int[] result = new int[4];
            for (int i = 0; i < 4; i++)
                for (int nibble = 0; nibble < 8; nibble++)
                    result[i] |= S(box, GetNibble(x[i], nibble)) << (nibble * 4);
            return result;
        }

        /// <returns>
        ///     A 128-bit entity being the result of applying, in parallel,
        ///     32 copies of the inverse of a given S-box to a 128-bit entity code>x</code>.
        /// </returns>
        private int[] ShatInverse(int box, int[] x)
        {
            int[] result = new int[4];
            for (int i = 0; i < 4; i++)
                for (int nibble = 0; nibble < 8; nibble++)
                    result[i] |= Sinverse(box, GetNibble(x[i], nibble)) << (nibble * 4);
            return result;
        }

        /// <returns>
        ///     A 128-bit entity being the result of applying the linear
        ///     transformation to a 128-bit entity <code>x</code>.
        /// </returns>
        private int[] LT(int[] x)
        {
            return Transform(LTtable, x);
        }

        /// <returns>
        ///     A 128-bit entity being the result of applying the inverse of
        ///     the linear transformation to a 128-bit entity <code>x</code>.
        /// </returns>
        private int[] LTinverse(int[] x)
        {
            return Transform(LTtableInverse, x);
        }

        /// <returns>
        ///     A 128-bit entity being the result of applying a transformation
        ///     coded in a table <code>T</code> to a 128-bit entity <code>x</code>.
        ///     Each row, of say index <code>i</code>, in <code>T</code> indicates
        ///     the bits from <code>x</code> to be XORed together in order to
        ///     produce the resulting bit at position <code>i</code>.
        /// </returns>
        private int[] Transform(byte[][] T, int[] x)
        {
            int j, b;
            int[] result = new int[4];
            for (int i = 0; i < 128; i++)
            {
                b = 0;
                j = 0;
                while (T[i][j] != xFF)
                {
                    b ^= GetBit(x, T[i][j] & 0x7F);
                    j++;
                }
                SetBit(result, i, b);
            }

            return result;
        }

        /// <returns>
        ///     The 128-bit entity as the result of applying the round function
        ///     R at round <code>i</code> to the 128-bit entity <code>Bhati</code>,
        ///     using the appropriate subkeys from <code>Khat</code>.
        /// </returns>
        private int[] R(int i, int[] Bhati, int[][] Khat)
        {
            int[] xored = xor128(Bhati, Khat[i]);
            int[] Shati = Shat(i, xored);
            int[] BhatiPlus1;
            if ((0 <= i) && (i <= Rounds - 2))
                BhatiPlus1 = LT(Shati);
            else if (i == Rounds - 1)
                BhatiPlus1 = xor128(Shati, Khat[Rounds]);
            else
                throw new Exception(
                    "Round " + i + " is out of 0.." + (Rounds - 1) + " range");

            return BhatiPlus1;
        }

        /// <returns>
        ///     The 128-bit entity as the result of applying the inverse of
        ///     the round function R at round <code>i</code> to the 128-bit
        ///     entity <code>Bhati</code>, using the appropriate subkeys from 
        ///     <code>Khat</code>.
        /// </returns>
        private int[] Rinverse(int i, int[] BhatiPlus1, int[][] Khat)
        {
            int[] Shati = new int[4];
            if ((0 <= i) && (i <= Rounds - 2))
                Shati = LTinverse(BhatiPlus1);
            else if (i == Rounds - 1)
                Shati = xor128(BhatiPlus1, Khat[Rounds]);
            else
                throw new Exception(
                    "Round " + i + " is out of 0.." + (Rounds - 1) + " range");

            int[] xored = ShatInverse(i, Shati);
            int[] Bhati = xor128(xored, Khat[i]);

            return Bhati;
        }

        /// <returns>
        ///     The 128-bit entity as the result of applying the inverse of
        ///     the round function R at round <code>i</code> to the 128-bit
        ///     entity <code>Bhati</code>, using the appropriate subkeys from 
        ///     <code>Khat</code>.
        /// </returns>
        private int[] Rinverse(int i, int[] BhatiPlus1, int[][] Khat, int inV, int val)
        {
            int[] Shati = new int[4];

            if ((0 <= i) && (i <= Rounds - 2))
                Shati = LTinverse(BhatiPlus1);
            else if (i == Rounds - 1)
                Shati = xor128(BhatiPlus1, Khat[Rounds]);
            else
                throw new Exception(
                    "Round " + i + " is out of 0.." + (Rounds - 1) + " range");

            int[] xored = ShatInverse(i, Shati);
            if (i == inV)
            {
                xored[0] = val | (val << 4);
                xored[0] |= (xored[0] << 8);
                xored[0] |= (xored[0] << 16);
                xored[1] = xored[2] = xored[3] = xored[0];
            }
            int[] Bhati = xor128(xored, Khat[i]);

            return Bhati;
        }
        #endregion

        #region Utility Methods
        // utility static methods (from cryptix.util.core.Hex class)
        //...........................................................................

        /// <returns>
        ///     A string of 8 hexadecimal digits (most significant
        ///     digit first) corresponding to the integer <i>n</i>, which is
        ///     treated as unsigned.
        /// </returns>
        public String intToString(int n)
        {
            char[] buf = new char[8];

            for (int i = 7; i >= 0; i--)
            {
                buf[i] = HEX_DIGITS[n & 0x0F];
                n = (int)((uint)n >> 4);
            }

            return new string(buf);
        }

        /// <returns>
        ///     A string of hexadecimal digits from a byte array. Each
        ///     byte is converted to 2 hex symbols.
        /// </returns>
        private string ToString(byte[] ba)
        {
            int length = ba.Length;
            char[] buf = new char[length * 2];
            for (int i = 0, j = 0, k; i < length; )
            {
                k = ba[i++];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 4)) & 0x0F];
                buf[j++] = HEX_DIGITS[k & 0x0F];
            }

            return new string(buf);
        }

        /// <returns>
        ///     A string of hexadecimal digits from an integer array. Each
        ///     int is converted to 4 hex symbols.
        /// </returns>
        private string ToString(int[] ia)
        {
            int length = ia.Length;
            char[] buf = new char[length * 8];
            for (int i = 0, j = 0, k; i < length; i++)
            {
                k = ia[i];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 28)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 24)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 20)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 16)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 12)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 8)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 4)) & 0x0F];
                buf[j++] = HEX_DIGITS[k & 0x0F];
            }

            return new string(buf);
        }

        // other utility static methods
        //...........................................................................

        /// <returns>
        ///     An hexadecimal number (respresented as a string of hexadecimal 
        ///     digits from a byte array). Each byte is converted to 2 hex symbols.
        ///     The order is however, as of printing a number from a little-endian
        ///     internal representation (i.e., reverse order).
        /// </returns>
        public string ToReversedString(byte[] ba)
        {
            int length = ba.Length;
            char[] buf = new char[length * 2];
            for (int i = length - 1, j = 0, k; i >= 0; )
            {
                k = ba[i--];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 4)) & 0x0F];
                buf[j++] = HEX_DIGITS[k & 0x0F];
            }
            return new string(buf);
        }

        /// <returns>
        ///     A string of hexadecimal digits from an integer array. Each
        ///     int is converted to 4 hex symbols.
        /// </returns>
        private static String ToReversedString(int[] ia)
        {
            int length = ia.Length;
            char[] buf = new char[length * 8];
            for (int i = length - 1, j = 0, k; i >= 0; i--)
            {
                k = ia[i];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 28)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 24)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 20)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 16)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 12)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 8)) & 0x0F];
                buf[j++] = HEX_DIGITS[((int)((uint)k >> 4)) & 0x0F];
                buf[j++] = HEX_DIGITS[k & 0x0F];
            }

            return new string(buf);
        }
        #endregion
    }
}
