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

build: deps test configure build-linux build-mac build-windows

bareback: deps configure build-linux build-mac build-windows

deps:
	go get -t ./...

test:
	go get golang.org/x/tools/cmd/cover
	go get github.com/mattn/goveralls
	go get github.com/sozorogami/gover
	
	go test -v "github.com/GESkunkworks/gossamer/acfmgr" -covermode=count -coverprofile=acfmgr.coverprofile
	go test -v "github.com/GESkunkworks/gossamer/gossamer" -covermode=count -coverprofile=gossamer.coverprofile
	gover
	goveralls -coverprofile gover.coverprofile -service=travis-ci -repotoken $(COVERALLS_TOKEN) 

configure:
	mkdir $(build_dir)
	mkdir $(build_dir_linux)
	mkdir $(build_dir_mac)
	mkdir $(build_dir_windows)


build-linux:
	export GOOS=linux
	export GOARCH=amd64
	go build -o ./$(build_dir_linux)/gossamer -ldflags "-X main.version=$(version)"
	chmod +x ./$(build_dir_linux)/gossamer 
	@cd ./$(build_dir_linux) && tar zcf ../$(build_dir)/$(packageNameNix) . 

build-mac:
	export GOOS=darwin
	export GOARCH=amd64
	go build -o ./$(build_dir_mac)/gossamer -ldflags "-X main.version=$(version)"
	./$(build_dir_mac)/gossamer 
	@cd ./$(build_dir_mac) && tar zcf ../$(build_dir)/$(packageNameMac) . 

build-windows:
	export GOOS=windows
	export GOARCH=amd64
	go build -o ./$(build_dir_windows)/gossamer.exe -ldflags "-X main.version=$(version)"
	@cd ./$(build_dir_windows) && tar zcf ../$(build_dir)/$(packageNameWindows) . 

clean:
	rm -f *.coverprofile
	rm -rf $(build_dir)
	rm -rf $(build_dir_linux)
	rm -rf $(build_dir_mac)
	rm -rf $(build_dir_windows)	