module github.com/blockchain-tps-test/samples/cosmos

go 1.16

require (
	github.com/cosmos/cosmos-sdk v0.45.8
	github.com/cosmos/ibc-go/v4 v4.1.0
	github.com/pkg/errors v0.9.1
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/sasha-s/go-deadlock v0.3.1 // indirect
	github.com/tendermint/tendermint v0.34.21
	google.golang.org/grpc v1.48.0
)

replace google.golang.org/grpc => google.golang.org/grpc v1.33.2

replace github.com/gogo/protobuf => github.com/regen-network/protobuf v1.3.3-alpha.regen.1
