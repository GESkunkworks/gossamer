// pipeline script to build gossamer and push build to s3 bucket
// depends on credentials being set up in Jenkins ahead of time
// along with the Go tools plugin.

def majVersion = '1'
def minVersion = '1'
def relVersion = '0'

def version = "${majVersion}.${minVersion}.${relVersion}.${env.BUILD_NUMBER}"
def packageNameNix = "gossamer-linux-amd64-${version}.tar.gz"
def packageNameNixLatest = "gossamer-linux-amd64-latest.tar.gz"
def packageNameMac = "gossamer-darwin-amd64-${version}.tar.gz"
def packageNameMacLatest = "gossamer-darwin-amd64-latest.tar.gz"
def bucketPath = "builds/"

try {
    node {
        withCredentials([string(credentialsId: 'cloudpod-slack-token', variable: 'SLACKTOKEN'),
                         string(credentialsId: 'cloudpod-slack-org', variable: 'SLACKORG'),
                         string(credentialsId: 'gossamer-builds-s3-bucket', variable: 'S3BUCKET')]) 
        {
            stage('cleanup') {
                deleteDir()
            }
            stage ('checkout source') {
                checkout scm
            }
            stage ('golang env setup') {
                // Install the desired Go version
                // Export environment variables pointing to the directory where Go was installed
                withEnv(["GOROOT=${tool 'golang180'}", "PATH+GO=${tool 'golang180'}/bin"]) {
                    sh 'go version'
                }
            }
            stage ('dependencies') {
                withEnv(["GOROOT=${tool 'golang180'}", "PATH+GO=${tool 'golang180'}/bin"]) {
                    sh "go get github.com/aws/aws-sdk-go/aws/session"
                    sh "go get github.com/aws/aws-sdk-go/service/sts"
                    sh "go get github.com/aws/aws-sdk-go/aws"
                    sh "go get github.com/aws/aws-sdk-go/aws/ec2metadata"
                    sh "go get github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds"
                    sh "go get github.com/aws/aws-sdk-go/aws/credentials"
                    sh "go get github.com/inconshreveable/log15"
                }
            }
            stage ('build nix') {
                withEnv(["GOOS=linux","GOARCH=amd64","GOROOT=${tool 'golang180'}", "PATH+GO=${tool 'golang180'}/bin"]) {
                    sh "go build -ldflags \"-X main.version=${version}\" gossamer.go"
                }
                stage ('package') {
                    sh "tar zcfv ${packageNameNix} gossamer"
                }
            }
            stage ('build mac') {
                withEnv(["GOOS=darwin","GOARCH=amd64","GOROOT=${tool 'golang180'}", "PATH+GO=${tool 'golang180'}/bin"]) {
                    sh "go build -ldflags \"-X main.version=${version}\" gossamer.go"
                }
                stage ('package') {
                    sh "tar zcfv ${packageNameMac} gossamer"
                }
            }
            stage ('artifact upload') {
                awsIdentity()
                s3Upload(file:"${packageNameNix}", bucket: "${S3BUCKET}", path:"${bucketPath}${packageNameNix}")
                s3Upload(file:"${packageNameNix}", bucket: "${S3BUCKET}", path:"${bucketPath}${packageNameNixLatest}")
                s3Upload(file:"${packageNameMac}", bucket: "${S3BUCKET}", path:"${bucketPath}${packageNameMac}")
                s3Upload(file:"${packageNameMac}", bucket: "${S3BUCKET}", path:"${bucketPath}${packageNameMacLatest}")
            }
            stage ('notify') {
                slackSend channel: '#cloudpod-feed', color: 'good', message: "gossamer build SUCCESS. Mac package: https://s3.amazonaws.com/${S3BUCKET}/${bucketPath}${packageNameMacLatest}, Nix package: https://s3.amazonaws.com/${S3BUCKET}/${bucketPath}${packageNameNixLatest}", teamDomain: "${SLACKORG}", token:"${SLACKTOKEN}"  
            }
        }
    }
} catch (error) {
    withCredentials([string(credentialsId: 'cloudpod-slack-token', variable: 'SLACKTOKEN'),
                     string(credentialsId: 'cloudpod-slack-org', variable: 'SLACKORG')])
    {
        stage ('notify failure') {
            slackSend channel: '#cloudpod-feed', color: 'bad', message: "gossamer build FAILED ${env.BUILD_URL}", teamDomain: "${SLACKORG}", token:"${SLACKTOKEN}"   
        }
    }
}
