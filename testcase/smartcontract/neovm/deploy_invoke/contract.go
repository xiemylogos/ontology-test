package deploy_invoke

import "github.com/ontio/ontology-go-sdk/utils"

//Smart contract code in hex string after compiled
var contractCode = "51c56b616168164e656f2e53746f726167652e476574436f6e746578740548656c6c6f05576f726c64615272680f4e656f2" +
	"e53746f726167652e50757461610568656c6c6f05776f726c64017b615272087472616e7366657254c168124e656f2e52756e74696d652e4e6" +
	"f74696679616168164e656f2e53746f726167652e476574436f6e746578740548656c6c6f617c680f4e656f2e53746f726167652e4765746c7" +
	"66b00527ac46203006c766b00c3616c7566"

//Address of smart contract
var contractCodeAddress = utils.GetNeoVMContractAddress(contractCode)

/*
   using Neo.SmartContract.Framework;
   using Neo.SmartContract.Framework.Services.Neo;
   using Neo.SmartContract.Framework.Services.System;
   using System;
   using System.ComponentModel;
   using System.Numerics;

   namespace NeoContract3
   {
       public class Contract1 : SmartContract
       {
           [DisplayName("transfer")]
           public static event Action<byte[], byte[], BigInteger> Transferred;

           public static object Main()
           {
			   Storage.Put(Storage.CurrentContext, "Hello", "World");
			   Transferred("hello".AsByteArray(), "world".AsByteArray(), 123);
			   return Storage.Get(Storage.CurrentContext, "Hello").AsString();

               return "123";
           }
       }
   }
*/
