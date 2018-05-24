package emergencyrpc

import (
	"github.com/ontio/ontology-test/testframework"
)

func TestEmergencyBlockRpc() {
	testframework.TFramework.RegTestCase("TestGenesisEmergencyBlock", TestGenesisEmergencyBlock)
}
