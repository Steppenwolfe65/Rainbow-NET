﻿using System;
using System.Diagnostics;
using Test.Tests;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Interfaces;
using VTDev.Libraries.CEXEngine.Crypto.Cipher.Asymmetric.Sign.RNBW;
using VTDev.Libraries.CEXEngine.Crypto.Enumeration;
using VTDev.Libraries.CEXEngine.Crypto.Prng;

namespace Test
{
    class Program
    {
        const int CYCLE_COUNT = 1000;
        const string CON_TITLE = "RNBW> ";

        #region Main
        static void Main(string[] args)
        {
            ConsoleUtils.SizeConsole(80, 60);
            ConsoleUtils.CenterConsole();
            Console.Title = "Rainbow Test Suite";

            // header
            Console.WriteLine("**********************************************");
            Console.WriteLine("* Rainbow Sign in C# (RNBW Sharp)            *");
            Console.WriteLine("*                                            *");
            Console.WriteLine("* Release:   v1.0                            *");
            Console.WriteLine("* Date:      July 04, 2015                   *");
            Console.WriteLine("* Contact:   develop@vtdev.com               *");
            Console.WriteLine("**********************************************");
            Console.WriteLine("");
            Console.WriteLine("COMPILE as Any CPU | Release mode, RUN the .exe for real timings");
            Console.WriteLine("");

            if (Debugger.IsAttached)
            {
                Console.WriteLine("You are running in Debug mode! Compiled times will be much faster..");
                Console.WriteLine("");
            }

            Console.WriteLine(CON_TITLE + "Run Validation Tests? Press 'Y' to run, any other key to skip..");
            ConsoleKeyInfo keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                // serialization tests
                Console.WriteLine("******TESTING KEY SERIALIZATION******");
                RunTest(new RNBWKeyTest());
                Console.WriteLine("");/**/

                Console.WriteLine("******TESTING PARAMETERS******");
                RunTest(new RNBWParamTest());
                Console.WriteLine("");/**/

                // sign and verify
                Console.WriteLine("******TESTING SIGNING FUNCTIONS******");
                RunTest(new RNBWSignTest());
                Console.WriteLine("");/**/
            }

            Console.WriteLine("");
            Console.WriteLine(CON_TITLE + "Run Sign and Verify Speed Tests? Press 'Y' to run, all other keys close..");
            keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                Console.WriteLine("");
                Console.WriteLine("******Looping: Sign and Verify Test******");
                Console.WriteLine(string.Format("Testing {0} Full Cycles, throws on all failures..", CYCLE_COUNT));
                Console.WriteLine("");
                try
                {
                    Console.WriteLine("Test cycle using the N33L5 parameter set.");
                    SignSpeed(CYCLE_COUNT);
                    Console.WriteLine("");
                }
                catch (Exception ex)
                {
                    Console.WriteLine("Loop test failed! " + ex.Message);
                }
            }

            Console.WriteLine("");
            Console.WriteLine(CON_TITLE + "Run Key Creation Speed Tests? Press 'Y' to run, any other key to skip..");
            keyInfo = Console.ReadKey();
            Console.WriteLine("");

            if (keyInfo.Key.Equals(ConsoleKey.Y))
            {
                KeyGenSpeed();
                Console.WriteLine("Speed Tests Completed!");
                Console.WriteLine("");
                Console.WriteLine(CON_TITLE + "All tests have completed, press any key to close..");
                Console.ReadKey();
            }
            else
            {
                Environment.Exit(0);
            }
        }

        static void RunTest(ITest Test)
        {
            try
            {
                Test.Progress -= OnTestProgress;
                Test.Progress += new EventHandler<TestEventArgs>(OnTestProgress);
                Console.WriteLine(Test.Description);
                Console.WriteLine(Test.Test());
                Console.WriteLine();
            }
            catch (Exception Ex)
            {
                Console.WriteLine("An error has occured!");
                Console.WriteLine(Ex.Message);
                Console.WriteLine("");
                Console.WriteLine(CON_TITLE + "Continue Testing? Press 'Y' to continue, all other keys abort..");
                ConsoleKeyInfo keyInfo = Console.ReadKey();

                if (!keyInfo.Key.Equals(ConsoleKey.Y))
                    Environment.Exit(0);
                else
                    Console.WriteLine();
            }
        }

        static void OnTestProgress(object sender, TestEventArgs e)
        {
            Console.WriteLine(e.Message);
        }
        #endregion

        #region Timing Tests
        static void KeyGenSpeed(int Iterations = 4)
        {
            Console.WriteLine(string.Format("N | L: Key creation average time over {0} passes:", Iterations));
            Stopwatch runTimer = new Stopwatch();

            double elapsed = KeyGenerator(Iterations, RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N33L5));
            Console.WriteLine(string.Format("N33 L5: avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} keys created in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Creation Rate is {0} keys per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
        }

        static double KeyGenerator(int Iterations, RNBWParameters Param)
        {
            // new SP20Prng(SeedGenerators.CSPRsg, 16384, 32, 10) // salsa20
            RNBWKeyGenerator mkgen = new RNBWKeyGenerator(Param, new CTRPrng(BlockCiphers.RDX, SeedGenerators.CSPRsg, 16384, 16));
            IAsymmetricKeyPair akp;
            Stopwatch runTimer = new Stopwatch();

            runTimer.Start();
            for (int i = 0; i < Iterations; i++)
                akp = mkgen.GenerateKeyPair();
            runTimer.Stop();

            return runTimer.Elapsed.TotalMilliseconds;
        }

        static void SignSpeed(int Iterations = 10)
        {
            Console.WriteLine(string.Format("N | L: Sign and Verify operations time over {0} passes:", Iterations));

            double elapsed = SignTest(Iterations, RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N33L5));
            Console.WriteLine(string.Format("N33 L5: messages signed avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} messages signed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Sign Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
            elapsed = SignTest(Iterations, RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N33L5), false);
            Console.WriteLine(string.Format("N33 L5: messages verified avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} messages verified in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Verify Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
            elapsed = SignTest(Iterations, RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N49L5));
            Console.WriteLine(string.Format("N49 L5: messages signed avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} messages signed in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Sign Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
            elapsed = SignTest(Iterations, RNBWParamSets.FromName(RNBWParamSets.RNBWParamNames.N49L5), false);
            Console.WriteLine(string.Format("N49 L5: messages verified avg. {0} ms", elapsed / Iterations, Iterations));
            Console.WriteLine(string.Format("{0} messages verified in: {1} ms", Iterations, elapsed));
            Console.WriteLine(string.Format("Verify Rate is {0} per second", (int)(1000.0 / (elapsed / Iterations))));
            Console.WriteLine("");
        }

        static double SignTest(int Iterations, RNBWParameters Param, bool Sign = true)
        {
            Stopwatch runTimer = new Stopwatch();
            byte[] code;
            RNBWKeyGenerator mkgen = new RNBWKeyGenerator(Param, new CTRPrng(BlockCiphers.RDX, SeedGenerators.CSPRsg, 16384, 16));
            IAsymmetricKeyPair akp = mkgen.GenerateKeyPair();
            byte[] data = new byte[200];
            new CSPRng().GetBytes(data);

            using (RNBWSign sgn = new RNBWSign(Param))
            {
                if (Sign)
                {
                    sgn.Initialize(akp.PrivateKey);

                    runTimer.Start();
                    for (int i = 0; i < Iterations; i++)
                        code = sgn.Sign(data, 0, data.Length);
                    runTimer.Stop();
                }
                else
                {
                    // sign the array first
                    sgn.Initialize(akp.PrivateKey);
                    code = sgn.Sign(data, 0, data.Length);
                    // init for verify
                    sgn.Initialize(akp.PublicKey);

                    runTimer.Start();
                    for (int i = 0; i < Iterations; i++)
                        sgn.Verify(data, 0, data.Length, code);
                    runTimer.Stop();
                }
            }

            return runTimer.Elapsed.TotalMilliseconds;
        }
        #endregion
    }
}
