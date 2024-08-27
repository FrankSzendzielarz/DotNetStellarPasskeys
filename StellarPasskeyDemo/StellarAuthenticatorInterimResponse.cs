using Fido2NetLib;
using StellarDotnetSdk.Operations;
using StellarDotnetSdk.Soroban;
using StellarDotnetSdk.Transactions;

namespace Fido2Demo
{
    public class StellarAuthenticatorInterimResponse
    {
        public AuthenticatorAssertionRawResponse TransactionAssertion { get; set; }
        public string TransactionData { get; set; }

        public uint LastLedger { get; set; }

    }

}
