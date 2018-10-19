// pipeline script to build gossamer and push build to s3 bucket
// depends on credentials being set up in Jenkins ahead of time
// and docker to be installed on agent

def majVersion = '1'
def minVersion = '2'
def relVersion = '2'

def version = "${majVersion}.${minVersion}.${relVersion}.${env.BUILD_NUMBER}"
def packageNameNix = "gossamer-linux-amd64-${version}.tar.gz"
def packageNameNixLatest = "gossamer-linux-amd64-latest.tar.gz"
def packageNameMac = "gossamer-darwin-amd64-${version}.tar.gz"
def packageNameMacLatest = "gossamer-darwin-amd64-latest.tar.gz"
def packageNameWindows = "gossamer-windows-amd64-${version}.tar.gz"
def packageNameWindowsLatest = "gossamer-windows-amd64-latest.tar.gz"
def bucketPath = "builds/"

try {
    node ("master"){
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
           stage ('build build docker') {
               sh "docker build . -t gossbuilder"
           }
           stage ('run build docker') {
               sh "docker run gossbuilder ./build.sh ${version} ${packageNameNix} ${packageNameMac} ${packageNameWindows} ${packageNameNixLatest} ${packageNameMacLatest} ${packageNameWindowsLatest} ${S3BUCKET} ${bucketPath}"
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
