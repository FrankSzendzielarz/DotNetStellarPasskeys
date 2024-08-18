using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Fido2NetLib;
using Fido2NetLib.Cbor;
using Fido2NetLib.Development;
using Fido2NetLib.Objects;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using PeterO.Cbor;
using StellarDotnetSdk;
using StellarDotnetSdk.Accounts;
using StellarDotnetSdk.LedgerKeys;
using StellarDotnetSdk.Operations;
using StellarDotnetSdk.Soroban;
using StellarDotnetSdk.Transactions;
using StellarDotnetSdk.Xdr;
using static StellarDotnetSdk.Xdr.ContractIDPreimage;
using static StellarDotnetSdk.Xdr.HashIDPreimage;

namespace Fido2Demo;

[Route("api/[controller]")]
public class MyController : Controller
{
    private IFido2 _fido2;
    public static IMetadataService _mds;
    public static readonly DevelopmentInMemoryStore DemoStorage = new();

    public MyController(IFido2 fido2)
    {
        _fido2 = fido2;
    }

    private string FormatException(Exception e)
    {
        return string.Format("{0}{1}", e.Message, e.InnerException != null ? " (" + e.InnerException.Message + ")" : "");
    }

    [HttpPost]
    [Route("/makeCredentialOptions")]
    public JsonResult MakeCredentialOptions([FromForm] string username,
                                            [FromForm] string displayName,
                                            [FromForm] string attType,
                                            [FromForm] string authType,
                                            [FromForm] string residentKey,
                                            [FromForm] string userVerification)
    {
        try
        {

            if (string.IsNullOrEmpty(username))
            {
                username = $"{displayName} (Usernameless user created at {DateTime.UtcNow})";
            }

            // 1. Get user from DB by username (in our example, auto create missing users)
            var user = DemoStorage.GetOrAddUser(username, () => new Fido2User
            {
                DisplayName = displayName,
                Name = username,
                Id = Encoding.UTF8.GetBytes(username) // byte representation of userID is required
            });

            // 2. Get user existing keys by username
            var existingKeys = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();

            // 3. Create options
            var authenticatorSelection = new AuthenticatorSelection
            {
                ResidentKey = residentKey.ToEnum<ResidentKeyRequirement>(),
                UserVerification = userVerification.ToEnum<UserVerificationRequirement>()
            };

            if (!string.IsNullOrEmpty(authType))
                authenticatorSelection.AuthenticatorAttachment = authType.ToEnum<AuthenticatorAttachment>();

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs() { Attestation = attType },
                CredProps = true
            };

            var options = _fido2.RequestNewCredential(user, existingKeys, authenticatorSelection, attType.ToEnum<AttestationConveyancePreference>(), exts);
            options.PubKeyCredParams = [
                PubKeyCredParam.ES256,  //restrict to Stellar Smart Account secp256r1 ecdsa
            ];
            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.attestationOptions", options.ToJson());

            // 5. return options to client
            return Json(options);
        }
        catch (Exception e)
        {
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeCredential")]
    public async Task<JsonResult> MakeCredential([FromBody] AuthenticatorAttestationRawResponse attestationResponse, CancellationToken cancellationToken)
    {
        try
        {
            // 1. get the options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.attestationOptions");
            var options = CredentialCreateOptions.FromJson(jsonOptions);

            // 2. Create callback so that lib can verify credential id is unique to this user
            IsCredentialIdUniqueToUserAsyncDelegate callback = static async (args, cancellationToken) =>
            {
                var users = await DemoStorage.GetUsersByCredentialIdAsync(args.CredentialId, cancellationToken);
                if (users.Count > 0)
                    return false;

                return true;
            };

          
            var credential = (await _fido2.MakeNewCredentialAsync(attestationResponse, options, callback, cancellationToken: cancellationToken)).Result;
            
            var cborObject = CBORObject.DecodeFromBytes(credential.PublicKey);
            var pk_x = cborObject[-2].GetByteString();
            var pk_y = cborObject[-3].GetByteString();
            
            byte[] pk_ecdsa= new byte[]{ 4 }.Concat(pk_x).Concat(pk_y).ToArray();

            // 3. Store the credentials in db
            DemoStorage.AddCredentialToUser(options.User, new StoredCredential
            {
                Id = credential.Id,
                PublicKey = credential.PublicKey,
                UserHandle = credential.User.Id,
                SignCount = credential.SignCount,
                AttestationFormat = credential.AttestationFormat,
                RegDate = DateTimeOffset.UtcNow,
                AaGuid = credential.AaGuid,
                Transports = credential.Transports,
                IsBackupEligible = credential.IsBackupEligible,
                IsBackedUp = credential.IsBackedUp,
                AttestationObject = credential.AttestationObject,
                AttestationClientDataJson = credential.AttestationClientDataJson,
                DevicePublicKeys = [credential.DevicePublicKey]
            });

       
            // The credential is registered, and the credential has an id and public key. 
            // These can now be used to deploy a Stellar Smart Account, which is an externally
            // deployed piece of authorisation logic that can be used as a gateway for
            // all kind of functionality. For example, the Smart Account could be the recipient
            // of a physical asset transfer in the real world, and the user of your system could via passkeys authorise
            // its subsequent sale.

            var json = await DeploySmartAccount(credential.Id, pk_ecdsa, cancellationToken);

            return json;
        }
        catch (Exception e)
        {
            return Json(new { status = "error", errorMessage = FormatException(e) });
        }
    }


  
    private async Task<JsonResult> DeploySmartAccount(byte[] credentialId, byte[] pk_ecdsa, CancellationToken cancellationToken)
    {
        try
        {
            string sorobanNetwork=Environment.GetEnvironmentVariable("SOROBAN_NETWORK");
            string sorobanNetworkPassphrase = Environment.GetEnvironmentVariable("SOROBAN_NETWORK_PASSPHRASE");
            string sorobanRpcServer= Environment.GetEnvironmentVariable("SOROBAN_RPC_URL");
            string ownerAccountPrivateKey = Environment.GetEnvironmentVariable("SOROBAN_ACCOUNT");
            string factoryContractId= Environment.GetEnvironmentVariable("factoryContractId"); //TODO remove factoryContractId it's a dup
            string horizonUrl= Environment.GetEnvironmentVariable("HORIZON_URL");

            //Network Id in XDR is represented as a hash.
            byte[] networkId = Util.Hash(Encoding.UTF8.GetBytes(sorobanNetworkPassphrase));
            byte[] credentialIdContractSalt = Util.Hash(credentialId);

            /*
             * If the smart account for this passkey id is already deployed, we should return an error.
             * To check if it already exists, we first need to generate the contract id for the smart account.
             * This consists of the id of the factory contract and a 'salt', which is populated here with the id of the passkey.
             * This is because the factory contract uses the "with_current_contract" to deploy. This method
             * allows for contract deployment with a deterministic id, that can be known in advance.
             * 
             * The code below could be written more concisely, but is expanded for clarity. 
             */

            #region Get the ID of the passkey's smart account, irrespective of whether it exists or not
            //A contract id preimage (prior to hashing) based on the smart contract address
            var contractIDPreimageFromAddress = new ContractIDPreimageFromAddress()
            {
                Address = new StellarDotnetSdk.Xdr.SCAddress()
                {
                    ContractId = new Hash(StrKey.DecodeContractId(factoryContractId)),
                    Discriminant = new SCAddressType() { InnerValue = SCAddressType.SCAddressTypeEnum.SC_ADDRESS_TYPE_CONTRACT }
                },
                Salt = new Uint256(credentialIdContractSalt)
            };

            // Create the HashIdPreimageContractId, which is just a union of the network id hash and the contract id preimage (iotw unhashed),
            // making a unique contract id. The naming is a bit opaque at first, more intuitive being something like 'network contract id'
            HashIDPreimageContractID contractIdPreimage = new HashIDPreimageContractID()
            {
                NetworkID = new Hash(networkId), //The XDR Hash object merely represents a hash, this ctor setting its inner value to the actual hash
                ContractIDPreimage = new StellarDotnetSdk.Xdr.ContractIDPreimage()
                {
                     FromAddress=contractIDPreimageFromAddress,
                     Discriminant=new ContractIDPreimageType() { InnerValue = ContractIDPreimageType.ContractIDPreimageTypeEnum.CONTRACT_ID_PREIMAGE_FROM_ADDRESS }
                }
            };
            
            // Make a general "Hash Id Preimage" object
            var hashIdPreImage = new HashIDPreimage();
            hashIdPreImage.Discriminant = new EnvelopeType() { InnerValue = EnvelopeType.EnvelopeTypeEnum.ENVELOPE_TYPE_CONTRACT_ID };
            hashIdPreImage.ContractID = contractIdPreimage;
            

            // Now the XDR representation is expected hashed and this gives the contract id
            XdrDataOutputStream xdrDataOutputStream = new XdrDataOutputStream();
            HashIDPreimage.Encode(xdrDataOutputStream, hashIdPreImage);
            var hashId = Util.Hash(xdrDataOutputStream.ToArray());

            //// The hash now needs to be used as a specific type of "String Key" (StrKey). The following function encodes the hashed data correctly, involving contract id type discriminators and checksums, in a human readable format.
            var contractId = StrKey.EncodeContractId(hashId);
         
            #endregion


            #region Ask the RPC Server for data on that smart contract
            Network network = new Network(sorobanNetworkPassphrase);
            Network.Use(network);
            
            SorobanServer server = new SorobanServer(sorobanRpcServer);
            
            
            List<StellarDotnetSdk.LedgerKeys.LedgerKey> ledgerKeys = new List<StellarDotnetSdk.LedgerKeys.LedgerKey>();
            SCContractId scContractId = new SCContractId(contractId);   // Make the contract id string a concrete type
            var key = new SCLedgerKeyContractInstance();                // Specifies to search for a contract instance
            var durability = new ContractDataDurability() { InnerValue = ContractDataDurability.ContractDataDurabilityEnum.PERSISTENT };
            StellarDotnetSdk.LedgerKeys.LedgerKey ledgerKey = StellarDotnetSdk.LedgerKeys.LedgerKey.ContractData(scContractId, key, durability);
            ledgerKeys.Add(ledgerKey);   //add the search key to a collection  

            var res=await server.GetLedgerEntries(ledgerKeys.ToArray());  
            if (res.LedgerEntries.Length > 0)
            {
                return Json(new { status = "error", errorMessage = "Smart Account already exists" });
            }

            #endregion

            #region Deploy the smart account
            KeyPair ownerAccount = KeyPair.FromSecretSeed(ownerAccountPrivateKey);
            var acctInfo = await server.GetAccount(ownerAccount.Address);
            Account ownerAccountData = new Account(acctInfo.AccountId, acctInfo.SequenceNumber);

            var simTxnBuilder = new TransactionBuilder(ownerAccountData);
            simTxnBuilder.SetFee(100);
            
            simTxnBuilder.AddOperation(
                new InvokeContractOperation(
                    new SCContractId(factoryContractId),
                    new StellarDotnetSdk.Soroban.SCSymbol("deploy"), 
                    [
                        new StellarDotnetSdk.Soroban.SCBytes(credentialIdContractSalt),
                        new StellarDotnetSdk.Soroban.SCBytes(pk_ecdsa) 
                    ]
                )
            );
            var simTxn=simTxnBuilder.Build();
            
            var sim=await server.SimulateTransaction(simTxn);

            if (sim.Error!=null)
            {
                return Json(new { status = "error", errorMessage = sim.Error });
            }
            
            
            simTxn.SetSorobanTransactionData(sim.SorobanTransactionData);
            simTxn.SetSorobanAuthorization(sim.SorobanAuthorization);
            simTxn.AddResourceFee(sim.MinResourceFee.Value);
            
            simTxn.Sign(ownerAccount);

            Server horizon = new Server(horizonUrl);
            
            var horizonResponse=await horizon.SubmitTransaction(simTxn);
            

    //        const txResp = await (await fetch(`${ PUBLIC_horizonUrl}/ transactions`, {
    //        method:
    //            'POST',
    //    headers:
    //            { 'Content-Type': 'application/x-www-form-urlencoded' },
    //    body:
    //            new URLSearchParams({ 'tx': transaction.toXDR() }),
    //})).json();

    //        if (txResp.successful)
    //        {
    //            return deployee
    //        }
    //        else
    //        {
    //            throw txResp
    //}


            #endregion



            return Json(new { status = "ok" });
            
        }
        catch (Exception e)
        {
            return Json(new { status = "error", errorMessage = FormatException(e) });
        }
    }


    [HttpPost]
    [Route("/assertionOptions")]
    public ActionResult AssertionOptionsPost([FromForm] string username, [FromForm] string userVerification)
    {
        try
        {
            var existingCredentials = new List<PublicKeyCredentialDescriptor>();

            if (!string.IsNullOrEmpty(username))
            {
                // 1. Get user from DB
                var user = DemoStorage.GetUser(username) ?? throw new ArgumentException("Username was not registered");

                // 2. Get registered credentials from database
                existingCredentials = DemoStorage.GetCredentialsByUser(user).Select(c => c.Descriptor).ToList();
            }

            var exts = new AuthenticationExtensionsClientInputs()
            {
                Extensions = true,
                UserVerificationMethod = true,
                DevicePubKey = new AuthenticationExtensionsDevicePublicKeyInputs()
            };

            // 3. Create options
            var uv = string.IsNullOrEmpty(userVerification) ? UserVerificationRequirement.Discouraged : userVerification.ToEnum<UserVerificationRequirement>();
            var options = _fido2.GetAssertionOptions(
                existingCredentials,
                uv,
                exts
            );

            // 4. Temporarily store options, session/in-memory cache/redis/db
            HttpContext.Session.SetString("fido2.assertionOptions", options.ToJson());

            // 5. Return options to client
            return Json(options);
        }

        catch (Exception e)
        {
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }

    [HttpPost]
    [Route("/makeAssertion")]
    public async Task<JsonResult> MakeAssertion([FromBody] AuthenticatorAssertionRawResponse clientResponse, CancellationToken cancellationToken)
    {
        try
        {
            // 1. Get the assertion options we sent the client
            var jsonOptions = HttpContext.Session.GetString("fido2.assertionOptions");
            var options = AssertionOptions.FromJson(jsonOptions);

            // 2. Get registered credential from database
            var creds = DemoStorage.GetCredentialById(clientResponse.Id) ?? throw new Exception("Unknown credentials");

            // 3. Get credential counter from database
            var storedCounter = creds.SignCount;

            // 4. Create callback to check if the user handle owns the credentialId
            IsUserHandleOwnerOfCredentialIdAsync callback = static async (args, cancellationToken) =>
            {
                var storedCreds = await DemoStorage.GetCredentialsByUserHandleAsync(args.UserHandle, cancellationToken);
                return storedCreds.Exists(c => c.Descriptor.Id.SequenceEqual(args.CredentialId));
            };

            // 5. Make the assertion
            var res = await _fido2.MakeAssertionAsync(clientResponse, options, creds.PublicKey, creds.DevicePublicKeys, storedCounter, callback, cancellationToken: cancellationToken);

            // 6. Store the updated counter
            DemoStorage.UpdateCounter(res.CredentialId, res.SignCount);

            if (res.DevicePublicKey is not null)
                creds.DevicePublicKeys.Add(res.DevicePublicKey);

            // 7. return OK to client
            return Json(res);
        }
        catch (Exception e)
        {
            return Json(new { Status = "error", ErrorMessage = FormatException(e) });
        }
    }
}
