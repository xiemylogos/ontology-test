package datatype

import (
	"time"

	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/utils"
	"github.com/ontio/ontology-test/testframework"
	"github.com/ontio/ontology/common"
)

func TestReturnType(ctx *testframework.TestFrameworkContext) bool {
	code := "55c56b6c766b00527ac46c766b51527ac46c766b52527ac46153c56c766b53527ac46c766b53c3006c766b00c3c46c766b53c3516c766b51c3c46c766b53c3526c766b52c3c46c766b53c36c766b54527ac46203006c766b54c3616c7566"
	codeAddress, _ := utils.GetContractAddress(code)
	signer, err := ctx.GetDefaultAccount()
	if err != nil {
		ctx.LogError("TestReturnType GetDefaultAccount error:%s", err)
		return false
	}
	_, err = ctx.Ont.Rpc.DeploySmartContract(ctx.GetGasPrice(), ctx.GetGasLimit(),
		signer,
		false,
		code,
		"TestReturnType",
		"1.0",
		"",
		"",
		"",
	)
	if err != nil {
		ctx.LogError("TestArray DeploySmartContract error:%s", err)
		return false
	}
	//等待出块
	_, err = ctx.Ont.Rpc.WaitForGenerateBlock(30*time.Second, 1)
	if err != nil {
		ctx.LogError("TestReturnType WaitForGenerateBlock error:%s", err)
		return false
	}
	if !testReturnType(ctx, codeAddress, []int{100343, 2433554}, []byte("Hello world")) {
		return false
	}
	return true
}

func testReturnType(ctx *testframework.TestFrameworkContext, code common.Address, args []int, arg3 []byte) bool {
	res, err := ctx.Ont.Rpc.PrepareInvokeNeoVMContractWithRes(
		code,
		[]interface{}{args[0], args[1], arg3},
		[]interface{}{sdkcom.NEOVM_TYPE_INTEGER, sdkcom.NEOVM_TYPE_INTEGER, sdkcom.NEOVM_TYPE_BYTE_ARRAY},
	)
	if err != nil {
		ctx.LogError("TestReturnType InvokeSmartContract error:%s", err)
		return false
	}

	rt, ok := res.([]interface{})
	if !ok {
		ctx.LogError("%s assert to array failed.", res)
		return false
	}

	err = ctx.AssertToInt(rt[0], args[0])
	if err != nil {
		ctx.LogError("TestReturnType AssertToInt error:%s", err)
		return false
	}

	err = ctx.AssertToInt(rt[1], args[1])
	if err != nil {
		ctx.LogError("TestReturnType AssertToInt error:%s", err)
		return false
	}

	err = ctx.AssertToByteArray(rt[2], arg3)
	if err != nil {
		ctx.LogError("AssertToByteArray error:%s", err)
		return false
	}

	return true
}

/*
using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using Neo.SmartContract.Framework.Services.System;
using System;
using System.Numerics;
namespace ONT_DEx
{
    public class ONT_P2P : SmartContract
    {
        public static object[] Main(int arg1, int arg2, byte[] arg3)
        {
            object[] ret = new object[3];
            ret[0] = arg1;
            ret[1] = arg2;
            ret[2] = arg3;
            return ret;
        }
    }
}
*/
