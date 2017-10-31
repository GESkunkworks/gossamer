#!/bin/bash
# e.g.,
# ./build.sh 0.1 pnix.tar.gz pmac.tar.gz pwin.tar.gz pnix-latest.tar.gz pmac-latest.tar.gz pwin-latest.tar.gz mybucket /mypath/
set -e
version=$1
packageNameNix=$2
packageNameMac=$3
packageNameWindows=$4
packageNameNixLatest=$5
packageNameMacLatest=$6
packageNameWindowsLatest=$7
S3BUCKET=$8
bucketPath=$9
mkdir build
export GOOS="linux"
export GOARCH="amd64"
go test ./... -v
go build -o ./build/gossamer -ldflags "-X main.version=$version"
cd ./build && tar zcfv ../$packageNameNix . && cd ..
export GOOS="darwin"
export GOARCH="amd64"
go build -o ./build/gossamer -ldflags "-X main.version=$version"
cd ./build && tar zcfv ../$packageNameMac . && cd ..
export GOOS="windows"
export GOARCH="amd64"
go build -o ./build/gossamer.exe -ldflags "-X main.version=$version"
cd ./build && tar zcfv ../$packageNameWindows . && cd ..
aws s3 cp $packageNameNix s3://$S3BUCKET/$bucketPath$packageNameNix
aws s3 cp $packageNameNix s3://$S3BUCKET/$bucketPath$packageNameNixLatest
aws s3 cp $packageNameMac s3://$S3BUCKET/$bucketPath$packageNameMac
aws s3 cp $packageNameMac s3://$S3BUCKET/$bucketPath$packageNameMacLatest
aws s3 cp $packageNameWindows s3://$S3BUCKET/$bucketPath$packageNameWindows
aws s3 cp $packageNameWindows s3://$S3BUCKET/$bucketPath$packageNameWindowsLatest
