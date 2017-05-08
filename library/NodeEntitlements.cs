using System;
using System.Collections.Immutable;
using System.Net;

namespace library
{
    public class NodeEntitlements
    {
        public string VirtualMachineId { get; } = "MyMachine";

        public DateTimeOffset Created { get; } = DateTimeOffset.Now;

        public DateTimeOffset NotBefore { get; } = DateTimeOffset.Now.AddMinutes(-1);

        public DateTimeOffset NotAfter { get; } = DateTimeOffset.Now.AddDays(7);

        public string Identifier { get; } = "26d3e7ce-548a-44e1-b1d6-07c073e83f72";
    }
}
