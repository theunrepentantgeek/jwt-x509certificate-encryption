using System;
using System.Diagnostics;
using System.Net;
using library;

namespace core
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                new Driver().TokenTest();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

            if (Debugger.IsAttached)
            {
                Console.ReadLine();
            }
        }
    }
}
