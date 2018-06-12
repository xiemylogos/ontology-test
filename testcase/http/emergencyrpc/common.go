package emergencyrpc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/ontio/ontology-crypto/keypair"
	"github.com/ontio/ontology-test/testframework"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology/common"
	"github.com/ontio/ontology/common/serialization"
	vbft "github.com/ontio/ontology/consensus/vbft"
	"github.com/ontio/ontology/consensus/vbft/config"
	"github.com/ontio/ontology/core/signature"
	"github.com/ontio/ontology/core/types"
	"github.com/ontio/ontology/core/utils"
	emergency "github.com/ontio/ontology/p2pserver/message/types"
	"github.com/ontio/ontology/smartcontract/service/native/governance"
	nutils "github.com/ontio/ontology/smartcontract/service/native/utils"
	"github.com/ontio/ontology/smartcontract/states"
	stypes "github.com/ontio/ontology/smartcontract/types"
)

func buildBlackTranaction(blockNum uint32, blackNodePub []string) (*types.Transaction, error) {
	params := &governance.BlackNodeParam{
		PeerPubkey: blackNodePub,
	}
	blacknodebf := new(bytes.Buffer)
	if err := params.Serialize(blacknodebf); err != nil {
		return nil, fmt.Errorf("Serialize BlackNodeParams error:%s", err)
	}

	init := states.Contract{
		Address: nutils.GovernanceContractAddress,
		Method:  governance.BLACK_NODE,
		Args:    blacknodebf.Bytes(),
	}
	bf := new(bytes.Buffer)
	init.Serialize(bf)
	vmCode := stypes.VmCode{
		VmType: stypes.Native,
		Code:   bf.Bytes(),
	}
	tx := utils.NewInvokeTransaction(vmCode)
	tx.Nonce = blockNum
	return tx, nil
}

func buildEmergencyBlock(ctx *testframework.TestFrameworkContext, user *account.Account, peerPubkeyList []string) ([]byte, error) {
	blkNum, err := ctx.Ont.Rpc.GetBlockCount()
	if err != nil {
		ctx.LogError("ctx.Ont.Rpc.GetBlockCount error:%s", err)
		return nil, false
	}
	block, err := getprevBlock(blkNum, ctx)
	if err != nil {
		return nil, err
	}
	tx, err := buildBlackTranaction(blkNum, peerPubkeyList)
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
	blk, err := constructBlock(user, blkNum, block.Hash(), blocktimestamp, sysTxs, consensusPayload, ctx)
	if err != nil {
		return nil, fmt.Errorf("constructBlock failed")
	}
	emergencyblock := &emergency.EmergencyActionRequest{
		Reason:         emergency.FalseConsensus,
		Evidence:       emergency.ConsensusMessage,
		ProposalBlkNum: bkNum,
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
