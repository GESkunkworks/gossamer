#versionMaj := 1
#versionMin := 2
#versionPatch := 3
#version := $(versionMaj).$(versionMin).$(versionPatch).$(TRAVIS_BUILD_NUMBER)
version := $(TRAVIS_TAG).$(TRAVIS_BUILD_NUMBER)

packageNameNix := gossamer-linux-amd64-$(version).tar.gz
packageNameMac := gossamer-darwin-amd64-$(version).tar.gz
packageNameWindows := gossamer-windows-amd64-$(version).tar.gz

build_dir := output
build_dir_linux := output-linux
build_dir_mac := output-mac
build_dir_windows := output-windows

# Can't use secrets in pull request builds
pr: testlite configure build-linux build-mac build-windows

nonpr: build

build: testfull configure build-linux build-mac build-windows

buildlocal: export TRAVIS_TAG = "9.9.9"
buildlocal: export TRAVIS_BUILD_NUMBER = "1"
buildlocal: testlite testlite configure build-linux build-mac build-windows

bare: configure build-linux build-mac build-windows

testlite:
	go get golang.org/x/tools/cmd/cover
	go get github.com/mattn/goveralls
	go get github.com/sozorogami/gover
	
	go test -v "github.com/GESkunkworks/gossamer/gossamer" -covermode=count -coverprofile=gossamer.coverprofile
	gover

testfull: testlite
	goveralls -coverprofile gover.coverprofile -service=travis-ci -repotoken $(COVERALLS_TOKEN) 


configure:
	mkdir $(build_dir)
	mkdir $(build_dir_linux)
	mkdir $(build_dir_mac)
	mkdir $(build_dir_windows)


build-linux:
	env GOOS=linux GOARCH=amd64 go build -o ./$(build_dir_linux)/gossamer -ldflags "-X main.version=$(version)"
	@cd ./$(build_dir_linux) && tar zcf ../$(build_dir)/$(packageNameNix) . 

build-mac:
	env GOOS=darwin GOARCH=amd64 go build -o ./$(build_dir_mac)/gossamer -ldflags "-X main.version=$(version)"
	@cd ./$(build_dir_mac) && tar zcf ../$(build_dir)/$(packageNameMac) . 

build-windows:
	env GOOS=windows GOARCH=amd64 go build -o ./$(build_dir_windows)/gossamer.exe -ldflags "-X main.version=$(version)"
	@cd ./$(build_dir_windows) && tar zcf ../$(build_dir)/$(packageNameWindows) . 

clean:
	rm -f *.coverprofile
	rm -rf $(build_dir)
	rm -rf $(build_dir_linux)
	rm -rf $(build_dir_mac)
	rm -rf $(build_dir_windows)	

format:
	gofmt -w ./gossamer/*.go
	gofmt -w ./*.go
	golint
	golint ./gossamer
	go vet
	go vet ./gossamer
	staticcheck
	staticcheck ./gossamer
	go build -o t main.go
