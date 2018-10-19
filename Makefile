#versionMaj := 1
#versionMin := 2
#versionPatch := 3
#version := $(versionMaj).$(versionMin).$(versionPatch).$(TRAVIS_BUILD_NUMBER)
version := $(TRAVIS_TAG).$(TRAVIS_BUILD_NUMBER)

packageNameNix := "gossamer-linux-amd64-$(version).tar.gz"
packageNameNixLatest := "gossamer-linux-amd64-latest.tar.gz"
packageNameMac := "gossamer-darwin-amd64-$(version).tar.gz"
packageNameMacLatest := "gossamer-darwin-amd64-latest.tar.gz"
packageNameWindows := "gossamer-windows-amd64-$(version).tar.gz"
packageNameWindowsLatest := "gossamer-windows-amd64-latest.tar.gz"

build_dir := "output"

build: deps test configure build-linux build-mac build-windows

deps:
	go get -t ./...

test:
	go get golang.org/x/tools/cmd/cover
	go get github.com/mattn/goveralls
	go test -v -covermode=count -coverprofile=coverage.out $(HOME)/gopath/bin/goveralls \
	   -coverprofile=coverage.out -service=travis-ci -repotoken $(COVERALLS_TOKEN) ./...

configure:
	mkdir $(build_dir)

build-linux:
	export GOOS="linux"
	export GOARCH="amd64"
	go build -o ./$(build_dir)/gossamer -ldflags "-X main.version=$(version)"
	cd ./$(build_dir) && tar zcfv ../$(packageNameNix) . && cd ..

build-mac:
	export GOOS="darwin"
	export GOARCH="amd64"
	go build -o ./$(build_dir)/gossamer -ldflags "-X main.version=$(version)"
	cd ./$(build_dir) && tar zcfv ../$(packageNameMac) . && cd ..

build-windows:
	export GOOS="windows"
	export GOARCH="amd64"
	go build -o ./$(build_dir)/gossamer.exe -ldflags "-X main.version=$(version)"
	cd ./$(build_dir) && tar zcfv ../$(packageNameWindows) . && cd ..
