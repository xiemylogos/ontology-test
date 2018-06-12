package emergencyrpc

import (
	"encoding/json"
	"io/ioutil"

	"github.com/ontio/ontology-test/common"
	"github.com/ontio/ontology-test/testframework"
	"github.com/ontio/ontology/account"
)

type EmergencyParam struct {
	Path           string
	PeerPubkeyList []string
}

func EmergencyBlock(ctx *testframework.TestFrameworkContext) bool {
	data, err := ioutil.ReadFile("./params/Emergency.json")
	if err != nil {
		ctx.LogError("ioutil.ReadFile failed %v", err)
		return nil, false
	}
	emergencyParam := new(EmergencyParam)
	err = json.Unmarshal(data, emergencyParam)
	if err != nil {
		ctx.LogError("json.Unmarshal failed %v", err)
		return nil, false
	}
	user, ok := getAccount(ctx, emergencyParam.Path)
	if !ok {
		return nil, false
	}
	block, err := buildEmergencyBlock(ctx, user, emergencyParam.PeerPubkeyList)
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

func getAccount(ctx *testframework.TestFrameworkContext, path string) (*account.Account, bool) {
	wallet, err := ctx.Ont.OpenWallet(path)
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
