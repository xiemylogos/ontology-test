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
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-test/testframework"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/serialization"
	vbft "github.com/ontio/ontology/consensus/vbft"
	"github.com/ontio/ontology/consensus/vbft/config"
	"github.com/ontio/ontology/core/signature"
	"github.com/ontio/ontology/core/types"
	httpcom "github.com/ontio/ontology/http/base/common"
	emergency "github.com/ontio/ontology/p2pserver/message/types"
	"github.com/ontio/ontology/smartcontract/service/native/governance"
	gover "github.com/ontio/ontology/smartcontract/service/native/governance"
	nutils "github.com/ontio/ontology/smartcontract/service/native/utils"
)

func buildBlackTranaction(ctx *testframework.TestFrameworkContext, blockNum uint32, blackNodePub []string) (*types.Transaction, error) {
	params := &governance.BlackNodeParam{
		PeerPubkeyList: blackNodePub,
	}
	var cversion = byte(0)

	invokeCode, err := httpcom.BuildNativeInvokeCode(nutils.GovernanceContractAddress, cversion, gover.BLACK_NODE, []interface{}{params})
	if err != nil {
		return nil, fmt.Errorf("BuildNativeInvokeCode error:%s", err)
	}
	tx := sdkcom.NewInvokeTransaction(ctx.GetGasPrice(), ctx.GetGasLimit(), invokeCode)
	tx.Nonce = blockNum
	return tx, nil
}

func buildEmergencyBlock(ctx *testframework.TestFrameworkContext, account *account.Account, peerPubkeyList []string) ([]byte, error) {
	blkNum, err := ctx.Ont.Rpc.GetBlockCount()
	if err != nil {
		ctx.LogError("ctx.Ont.Rpc.GetBlockCount error:%s", err)
		return nil, err
	}
	block, err := getprevBlock(blkNum, ctx)
	if err != nil {
		return nil, err
	}
	tx, err := buildBlackTranaction(ctx, blkNum, peerPubkeyList)
	if err != nil {
		return nil, err
	}
	sysTxs := make([]*types.Transaction, 0)
	sysTxs = append(sysTxs, tx)
	consensusPayload, err := getconsensusPaylaod(ctx, block)
	if err != nil {
		return nil, err
	}
	blocktimestamp := uint32(time.Now().Unix())
	if block.Header.Timestamp >= blocktimestamp {
		blocktimestamp = block.Header.Timestamp + 1
	}
	blk, err := constructBlock(account, blkNum, block.Hash(), blocktimestamp, sysTxs, consensusPayload, ctx)
	if err != nil {
		return nil, fmt.Errorf("constructBlock failed")
	}
	emergencyblock := &emergency.EmergencyActionRequest{
		Reason:         emergency.FalseConsensus,
		Evidence:       emergency.ConsensusMessage,
		ProposalBlkNum: blkNum,
		ProposalBlk:    blk,
		ProposerPK:     account.PublicKey,
		ReqPK:          account.PublicKey,
	}
	blkHash := blk.Hash()
	blocksig, err := signature.Sign(account, blkHash[:])
	if err != nil {
		return nil, fmt.Errorf("sign block failed, block hash：%x, error: %s", blkHash, err)
	}
	emergencyblock.ProposerSigOnBlk = blocksig

	buf := new(bytes.Buffer)
	buf.Write([]byte{byte(emergencyblock.Reason), byte(emergencyblock.Evidence)})
	serialization.WriteUint32(buf, emergencyblock.ProposalBlkNum)
	emergencyblock.ProposalBlk.Serialize(buf)
	serialization.WriteVarBytes(buf, keypair.SerializePublicKey(emergencyblock.ProposerPK))
	serialization.WriteVarBytes(buf, emergencyblock.ProposerSigOnBlk)

	emergencysig, err := signature.Sign(account, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("sign block failed, block hash：%x, error: %s", blkHash, err)
	}
	adminsig := &types.Sig{
		PubKeys: []keypair.PublicKey{account.PublicKey},
		M:       1,
		SigData: [][]byte{emergencysig},
	}
	emergencyblock.AdminSigs = []*types.Sig{adminsig}
	emergencyHash := emergencyblock.Hash()
	reqSig, _ := signature.Sign(account, emergencyHash[:])
	emergencyblock.ReqSig = reqSig
	emergency := new(bytes.Buffer)
	if err := emergencyblock.Serialize(emergency); err != nil {
		return nil, fmt.Errorf("Serialize emergencyblock error:%s", err)
	}
	return emergency.Bytes(), nil
}

func getprevBlock(blkNum uint32, ctx *testframework.TestFrameworkContext) (*types.Block, error) {
	blk, err := ctx.Ont.Rpc.GetBlockByHeight(blkNum - 1)
	if err != nil {
		return nil, err
	}
	return blk, nil
}

func getconsensusPaylaod(ctx *testframework.TestFrameworkContext, blk *types.Block) ([]byte, error) {
	block, err := initVbftBlock(blk)
	if err != nil {
		return nil, err
	}
	lastConfigBlkNum := block.Info.LastConfigBlockNum
	if block.Info.NewChainConfig != nil {
		lastConfigBlkNum = block.Block.Header.Height
	}
	vbftBlkInfo := &vconfig.VbftBlockInfo{
		Proposer:           math.MaxUint32,
		LastConfigBlockNum: lastConfigBlkNum,
		NewChainConfig:     nil,
	}
	consensusPayload, err := json.Marshal(vbftBlkInfo)
	if err != nil {
		return nil, err
	}
	return consensusPayload, nil
}

func getblockRoot(ctx *testframework.TestFrameworkContext, txroot common.Uint256) (common.Uint256, error) {
	blkroot, err := ctx.Ont.Rpc.GetBlockRootWithNewTxRoot(txroot)
	if err != nil {
		return common.Uint256{}, err
	}
	return blkroot, nil
}

func constructBlock(account *account.Account, blkNum uint32, prevBlkHash common.Uint256, blocktimestamp uint32, systxs []*types.Transaction, consensusPayload []byte, ctx *testframework.TestFrameworkContext) (*types.Block, error) {
	txHash := []common.Uint256{}
	for _, t := range systxs {
		txHash = append(txHash, t.Hash())
	}
	txRoot := common.ComputeMerkleRoot(txHash)
	blockRoot, err := getblockRoot(ctx, txRoot)
	if err != nil {
		return nil, err
	}

	blkHeader := &types.Header{
		PrevBlockHash:    prevBlkHash,
		TransactionsRoot: txRoot,
		BlockRoot:        blockRoot,
		Timestamp:        blocktimestamp,
		Height:           uint32(blkNum),
		ConsensusData:    common.GetNonce(),
		ConsensusPayload: consensusPayload,
	}
	blk := &types.Block{
		Header:       blkHeader,
		Transactions: systxs,
	}
	blkHash := blk.Hash()
	sig, err := signature.Sign(account, blkHash[:])
	if err != nil {
		return nil, fmt.Errorf("sign block failed, block hash：%x, error: %s", blkHash, err)
	}
	blkHeader.Bookkeepers = []keypair.PublicKey{account.PublicKey}
	blkHeader.SigData = [][]byte{sig}
	return blk, nil
}

func initVbftBlock(block *types.Block) (*vbft.Block, error) {
	if block == nil {
		return nil, fmt.Errorf("nil block in initVbftBlock")
	}

	blkInfo := &vconfig.VbftBlockInfo{}
	if err := json.Unmarshal(block.Header.ConsensusPayload, blkInfo); err != nil {
		return nil, fmt.Errorf("unmarshal blockInfo: %s", err)
	}

	return &vbft.Block{
		Block: block,
		Info:  blkInfo,
	}, nil
}
