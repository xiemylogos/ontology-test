package http

import (
	"github.com/ontio/ontology-test/testcase/http/emergencyrpc"
	"github.com/ontio/ontology-test/testcase/http/jsonrpc"
)

func TestHttp() {
	jsonrpc.TestRpc()
	emergencyrpc.TestEmergencyBlockRpc()
}
