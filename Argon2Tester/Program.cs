using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Argon2Managed;

namespace Argon2Managed.Tester
{
    class Program
    {
        static void Main(string[] args)
        {
            if (!LoadBlakeTests())
            {
                WriteThis("==Blake Tests COMPLETE: ", false, WType.Info);
                WriteThis(" ***FAIL***", true, WType.Error);
            }
            else
            {
                WriteThis("==Blake Tests COMPLETE: ", false, WType.Info);
                WriteThis(" ---PASS---", true, WType.Awesome);
            }
            if (!LoadArgon2Tests())
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.ForegroundColor = ConsoleColor.Red;
                WriteThis("==ARGON2 TESTS COMPLETE: ", false, WType.Info);
                WriteThis(" ***FAIL***", true, WType.Error);
            }
            else
            {
                WriteThis("==ARGON2 TESTS COMPLETE: ", false, WType.Info);
                WriteThis(" ---PASS---", true, WType.Awesome);
            }//*/
            WriteThis("==Password Practicality Tests (customized for individual needs, no known answers)");
            UTF8Encoding utf8 = new UTF8Encoding();
            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
            sw.Start();
            //Adjust these to your liking for testing various parameters.
            //The ComputerEncodedHash version will output a string showing most of the parameters for some variability in-situ
            uint t_cost = 2048;
            uint mem_cost = 96;
            uint lanes = 6;
            uint outLength = 8;
            int ret = Argon2.ComputeEncodedHash(
                utf8.GetBytes("stufffffffffflongPASSSSSSSSSSSSSSSSS"), // password
                utf8.GetBytes("So salty.  I really should stop eating Ramen Noodles"), //salt
                outLength, 
                Argon2Type.id, // type is Argon2Type.d, .i, or .id, i removes timing attacks but is slightly less secure
                utf8.GetBytes("shhhhhhh secret"), // secret
                utf8.GetBytes("The mitochondria are the powerhouse of the cell!"), // additional data
                t_cost, 
                mem_cost, 
                lanes, 
                out byte[] output,
                out string encoded);
            sw.Stop();
            Console.WriteLine("Time taken: " + sw.Elapsed.ToString() + "\r\n");
            Console.WriteLine("Encoded Output (next line):\r\n" + encoded);
            Console.WriteLine("Press ENTER to exit...");
            Console.ReadLine();
        }

        static bool LoadBlakeTests()
        {
            string Input = null;
            string Key = null;
            string Result = null;
            string Type = null;
            bool AllGood = true;
            WriteThis("==BLAKE TESTS===========================================================================", true, WType.Heading);
            foreach (string line in Properties.Resources.TESTS.Split(new string[] { "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries))
            {
                if (line.Contains("hash")) { Type = line; continue; }
                if (line.Contains("in")) { Input = line; continue; }
                if (line.Contains("out")) { Result = line; continue; }
                if (line.Contains("key")) { Key = line; continue; }

                if (Type != null && Input != null && Result != null & Key != null)
                {                
                    Input = Input.Substring(Input.IndexOf(":") + 1).Replace("\"", "").Replace(",", "").Trim();
                    Key = Key.Substring(Key.IndexOf(":") + 1).Replace("\"", "").Replace(",", "").Trim();
                    Result = Result.Substring(Result.IndexOf(":") + 1).Replace("\"", "").Replace(",", "").Trim();
                    byte[] KeyBytes = HexString2Bytes(Key);
                    byte[] InputBytes = HexString2Bytes(Input);
                    byte[] h = new byte[0];
                    if (Type.Contains("blake2s\""))
                    {
                        WriteThis("Testing " + Type + ", |Key|=" + KeyBytes.Length + " |Input|=" + InputBytes.Length + " |OutputLength|=" + (Result.Length / 2), false);
                        Blake2s b = new Blake2s(KeyBytes, (byte)(Result.Length / 2));
                        h = b.ComputeHash(InputBytes);
                    }
                    else if (Type.Contains("blake2b\""))
                    {
                        WriteThis("Testing " + Type + ", |Key|=" + KeyBytes.Length + " |Input|=" + InputBytes.Length + " |OutputLength|=" + (Result.Length / 2), false);
                        Blake2b b = new Blake2b(KeyBytes, (byte)(Result.Length / 2));
                        h = b.ComputeHash(InputBytes);
                    }
                    else
                    {
                        //Console.WriteLine("-SKIPPING-");
                        Type = Input = Result = Key = null;
                        continue;
                    }
                    if (BitConverter.ToString(h).Replace("-", "").ToLower() != Result)
                    {
                        WriteThis("  **FAIL**", true, WType.Error);
                        AllGood = false;
                        break;
                    }
                    else
                        WriteThis("  --PASS--", true, WType.Awesome);
                    Type = Input = Result = Key = null;
                }
            }

            return AllGood;
        }

        private struct argon_test
        {
            public UInt32 time;
            public UInt32 mem;
            public UInt32 lanes;
            public byte[] pass;
            public byte[] salt;
            public string hexResult;
            public byte[] ad;
            public byte[] secret; 
        }

        static bool LoadArgon2Tests()
        {
            //Console.WriteLine("Pausing 1 sec for command window...");
            //System.Threading.Thread.Sleep(1000);
            byte[] pass1 = ASCIIEncoding.ASCII.GetBytes("password");
            byte[] salt1 = ASCIIEncoding.ASCII.GetBytes("somesalt");
            WriteThis("==ARGON TESTS===========================================================================", true, WType.Heading);
            argon_test[] tests = new argon_test[]
            {
                // the following are from the KATS in GitHub for the official repository
                new argon_test { time = 3, mem = 32, lanes=4,
                    pass = new byte[]{1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 },
                    salt =  new byte[]{ 2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2},
                    hexResult = "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
                    secret = new byte[]{ 3,3,3,3,3,3,3,3 },
                    ad = new byte[] { 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4 } },
                // the following are from the reference test program
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,16), lanes=1,
                    pass = pass1, salt = salt1 , hexResult = "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0", secret= null, ad=null},
#if HIGH_MEM
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,20), lanes=1, // this will consume a GB of storage for the process!!
                    pass = pass1, salt = salt1, hexResult = "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41", secret= null, ad=null},
#endif
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,18), lanes=1,
                    pass = pass1, salt = salt1, hexResult = "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb", secret= null, ad=null},
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,8), lanes=1,
                    pass = pass1, salt = salt1, hexResult = "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f", secret= null, ad=null},
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,8), lanes=2,
                    pass = pass1, salt = salt1, hexResult = "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61", secret= null, ad=null},
                new argon_test { time = 1, mem = (UInt32)Math.Pow(2,16), lanes=1,
                    pass = pass1, salt = salt1, hexResult = "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf", secret= null, ad=null},
                new argon_test { time = 4, mem = (UInt32)Math.Pow(2,16), lanes=1,
                    pass = pass1, salt = salt1, hexResult = "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b", secret= null, ad=null},
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,16), lanes=1,
                    pass = ASCIIEncoding.ASCII.GetBytes("differentpassword"), salt = salt1, hexResult = "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
                    secret = null, ad=null},
                new argon_test { time = 2, mem = (UInt32)Math.Pow(2,16), lanes=1,
                    pass = pass1, salt = ASCIIEncoding.ASCII.GetBytes("diffsalt"), hexResult = "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
                    secret = null, ad=null}
            };

            string testhexresult;
            byte[] output;
            string outputString;
            int ret;
            System.Threading.Thread.Sleep(2000);
            System.Diagnostics.Stopwatch sw = new System.Diagnostics.Stopwatch();
            foreach (argon_test t in tests)
            {
                sw.Reset();
                outputString = null;
                output = null;
                Console.Write(string.Format("ARGON TEST t={0}, mem={1}, lanes={2}, result={3}, ", t.time, t.mem, t.lanes, t.hexResult));
                sw.Start();
                ret = Argon2.ComputeEncodedHash(t.pass, t.salt, 32, Argon2Type.i, t.secret, t.ad, t.time, t.mem, t.lanes, out output, out outputString);
                sw.Stop();
                Console.Write(" time taken: " + sw.Elapsed.ToString() + " ");
                testhexresult = Bytes2HexString(output);
                if (t.hexResult.CompareTo(testhexresult) != 0 || ret != 0)
                {
                    WriteThis(" ***FAIL*** RET=" + Argon2.ErrorMessage(ret), true, WType.Error);
                    return false;
                }
                else
                {
                    GC.Collect();
                    ret = Argon2.VerifyEncodedHash(t.pass, t.secret, t.ad, outputString);
                    if ( ret != 0)
                    {
                        WriteThis(" -COMPUTE/VERIFY FAIL**** RET=" + Argon2.ErrorMessage(ret), true, WType.Error);
                        return false;
                    }
                    else
                    {
                         WriteThis(" -COMPUTE/VERIFY PASS- ", true, WType.Awesome);
                    }
                }
                GC.Collect();
            }

            return true;
        }

        static byte[] HexString2Bytes(string input)
        {
            byte[] output = new byte[input.Length / 2];
            for (int i = 0; i < input.Length; i+=2)
            {
                output[i / 2] = byte.Parse(input.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
            }
            return output;
        }

        static string Bytes2HexString(byte[] input)
        {
            if (input == null) return "";
            string output = BitConverter.ToString(input).Replace("-", "").ToLower();
            return output;
        }

        public enum WType : byte
        {
            Normal = 0,
            Error = 1,
            Info = 2,
            Awesome = 4,
            Heading = 8
        }

        static void WriteThis(string message, bool crlf = true, WType type = WType.Normal)
        {
            ConsoleColor temp = Console.ForegroundColor;

            switch (type)
            {
                case WType.Error: Console.ForegroundColor = ConsoleColor.Red; break;
                case WType.Awesome: Console.ForegroundColor = ConsoleColor.Green; break;
                case WType.Heading: Console.ForegroundColor = ConsoleColor.Cyan; break;
                case WType.Info: Console.ForegroundColor = ConsoleColor.Yellow; break;
                case WType.Normal:
                default:
                    Console.ForegroundColor = ConsoleColor.Gray; break;
            }
            Console.Write(message);
            if (crlf) Console.WriteLine();
            Console.ForegroundColor = temp;
        }
    }
}
