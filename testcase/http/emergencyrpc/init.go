package emergencyrpc

import (
	"github.com/ontio/ontology-test/testframework"
)

func TestEmergencyBlockRpc() {
	testframework.TFramework.RegTestCase("EmergencyBlock", EmergencyBlock)
	//testframework.TFramework.RegTestCase("TestGlobalParam", TestGlobalParam)
}
