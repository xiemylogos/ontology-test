package emergencyrpc

import (
	"github.com/ontio/ontology-test/testframework"
	"github.com/ontio/ontology-test/common"
	"github.com/ontio/ontology/account"
)

func TestGenesisEmergencyBlock(ctx *testframework.TestFrameworkContext) bool {
	blknum, err := ctx.Ont.Rpc.GetBlockCount()
	if err != nil {
		ctx.LogError("ctx.Ont.Rpc.GetBlockCount error:%s", err)
		return false
	}

	block, err := buildEmergencyBlock(blknum,ctx)
	if err != nil {
		ctx.LogError("buildEmergencyBlock error:%s", err)
		return false
	}
	err = ctx.Ont.Rpc.SendEmergencyGovReq(block)
	if err != nil {
		ctx.LogError("ctx.Ont.Rpc.SendEmergencyGovReq error:%s", err)
	}
	return true
}

func getAccount(ctx *testframework.TestFrameworkContext) (*account.Account, bool) {
	wallet, err := ctx.Ont.OpenWallet("./testcase/http/blockrpc/wallet1.dat")
	if err != nil {
		ctx.LogError("open wallet error:%s", err)
		return nil, false
	}
	user, err := wallet.GetDefaultAccount([]byte(common.DefConfig.Password))
	if err != nil {
		ctx.LogError("getDefaultAccount error:%s", err)
		return nil, false
	}
	return user, true
}

