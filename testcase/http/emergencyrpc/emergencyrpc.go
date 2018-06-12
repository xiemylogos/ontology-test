/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */
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
