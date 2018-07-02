import boto3

session = boto3.Session(region_name="us-east-2")
client = session.client("codebuild")
response = client.start_build(
    projectName='goss-build',
)

print response