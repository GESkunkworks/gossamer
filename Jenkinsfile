// pipeline script to build gossamer and push build to s3 bucket
// depends on credentials being set up in Jenkins ahead of time
// along with the Go tools plugin.

def majVersion = '1'
def minVersion = '0'
def relVersion = '2'

def version = "${majVersion}.${minVersion}.${relVersion}.${env.BUILD_NUMBER}"
def packageName = "gossamer-${version}.tar.gz"
def packageNameLatest = "gossamer-latest.tar.gz"
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
                    sh "go get github.com/inconshreveable/log15"
                }
            }
            stage ('build') {
                withEnv(["GOROOT=${tool 'golang180'}", "PATH+GO=${tool 'golang180'}/bin"]) {
                    sh "go build -ldflags \"-X main.version=${version}\" gossamer.go"
                }
            }
            stage ('package') {
                sh "tar zcfv ${packageName} gossamer"
            }
            stage ('artifact upload') {
                awsIdentity()
                s3Upload(file:"${packageName}", bucket: "${S3BUCKET}", path:"${bucketPath}${packageName}")
                s3Upload(file:"${packageName}", bucket: "${S3BUCKET}", path:"${bucketPath}${packageNameLatest}")
            }
            stage ('notify') {
                slackSend channel: '#cloudpod-feed', color: 'good', message: "gossamer build SUCCESS ${env.BUILD_URL}", teamDomain: "${SLACKORG}", token:"${SLACKTOKEN}"  
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
