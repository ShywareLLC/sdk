module shyware-chaincode

go 1.19

require (
	github.com/hyperledger/fabric-chaincode-go v0.0.0-20230731094759-d626e9ab09b9
	github.com/hyperledger/fabric-protos-go v0.3.3
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	golang.org/x/net v0.20.0 // indirect
	golang.org/x/sys v0.16.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	google.golang.org/genproto v0.0.0-20230410155749-daa745c078e1 // indirect
	google.golang.org/grpc v1.56.3 // indirect
	google.golang.org/protobuf v1.32.0 // indirect
)

// Fabric 2.2 chaincode builder runs Go 1.14; //go:build was introduced in
// Go 1.17 (Aug 2021) and many packages dropped the compat // +build tag after
// Go 1.18 (Mar 2022). Pin all x/* and grpc to Oct 2020 releases which have
// no //go:build directives at all.
replace (
	golang.org/x/net => golang.org/x/net v0.0.0-20201021035429-f5854403a974
	golang.org/x/sys => golang.org/x/sys v0.0.0-20201020230747-6e5568b54d1a
	golang.org/x/text => golang.org/x/text v0.3.4
	google.golang.org/grpc => google.golang.org/grpc v1.35.0
)
