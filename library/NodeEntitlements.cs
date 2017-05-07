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

        public ImmutableHashSet<string> Applications { get; }

        public ImmutableHashSet<IPAddress> IpAddresses { get; }

        public string Identifier { get; } = "26d3e7ce-548a-44e1-b1d6-07c073e83f72";

        public NodeEntitlements()
        {
            Applications = ImmutableHashSet<string>.Empty.Add("app");
            IpAddresses = ImmutableHashSet<IPAddress>.Empty.Add(IPAddress.Parse("127.0.0.1"));
        }
    }
}
