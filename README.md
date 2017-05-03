# gossamer
Service to continuously build aws credentials file with sts assume-role token based on the instance profile.
Specifically designed for an instance profile role to assume-role in another AWS account.

Builds your `./.aws/credentials` file to look like this based on your current EC2 instance profile
```

####################################################
# DO NOT EDIT
# GOSSAMER MANAGED FILE
# (Will be overwritten regularly)
####################################################
[default]
# ASSUMED ROLE: arn:aws:iam::123456789101:role/collectd-cloudwatch-putter
# ASSUMED FROM INSTANCE ROLE: arn:aws:iam::987654321123:instance-profile/vESG-EC2
# GENERATED: 2017-05-02 04:25:02.578845609 +0000 UTC
# EXPIRES@2017-05-02 05:25:05 +0000 UTC
output = json
region = us-east-1
aws_access_key_id = ASIAIB123452NC2SX67
aws_secret_access_key = +3+AOLzPQnevergonnagiveyouupCrjsAV1fmDBwhlnUFsY
aws_session_token = FQoDYXdzEJ7//////////wEaDCN94Jg9dZc0Az7UWiLLAVfRnQiephwR+DrYFK9sFSxLa05B4dO3Ttw8CxHb/lhi1kEeZOa3DVhO1kg+I/ojgE4kKV0SETNc/hIqxa17nR2JnJU7WwxI6xunVppvqD+4n6RaV9wVSMJL7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaGUoMgF
####################################################
```

## IAM Policy Prereqs Example
For the example of using the EC2 instance profile in one account to assume-role in another account you would set up the following policies and trust:

**In Account1 (where you're assuming FROM)**

*EC2 instance profile in account 987654321123*
```
{
	"Action": [
		"sts:AssumeRole"
	],
	"Resource": [
		"arn:aws:iam::123456789101:role/collectd-cloudwatch-putter"
	],
	"Effect": "Allow"
}
```

**In Account2 (where you're assuming TO)**

*collectd-cloudwatch-putter Policy in account 123456789101*
```
{
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Action": [
			"cloudwatch:PutMetricData"
		],
		"Resource": [
			"*"
		]
	}]
}
```

*Trust document for collectd-cloudwatch-putter*
```
{
	"Version": "2012-10-17",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": "arn:aws:iam::987654321123:root"
		},
		"Action": "sts:AssumeRole"
	}]
}
```

## Build/Run from Source

```
go get github.com/aws/aws-sdk-go/aws/session
go get github.com/aws/aws-sdk-go/service/sts
go get github.com/aws/aws-sdk-go/aws
go get github.com/aws/aws-sdk-go/aws/ec2metadata
go get github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds
go get github.com/inconshreveable/log15
go build -ldflags "-X main.version=v0.0.0" gossamer.go
sudo mv gossamer.go /usr/bin/gossamer
```

## Usage
Here's the output of the contextual `--help` flag:
```
[ec2-user@ip-10-17-143-217 gossamer]$ go run gossamer.go --help
Usage of /tmp/go-build768499223/command-line-arguments/_obj/exe/gossamer:
  -a string
    	Role ARN to assume.
  -daemon
    	run as daemon checking every -s duration
  -duration int
    	Duration of token in seconds. (default 3600)
  -logfile string
    	JSON logfile location (default "gossamer.log.json")
  -o string
    	Output credentials file. (default "./gossamer_creds")
  -s int
    	Duration in seconds to wait between checks. (default 300)
  -t int
    	 threshold in minutes. (default 10)
  -v	print version and exit
exit status 2
```

Test the command like so using the assumeRole that is allowed per your instance profile:
```
sudo /usr/bin/gossamer -o /root/.aws/credentials -a arn:aws:iam::123456789101:role/collectd-cloudwatch-putter -t 12
```
You should see an output similar to the following:
```
t=2017-05-03T20:18:30+0000 lvl=info msg="gossamer: assume-role via instance role" version=
t=2017-05-03T20:18:31+0000 lvl=info msg=OPTIONS parsed outfile=./gossamer_creds
t=2017-05-03T20:18:31+0000 lvl=info msg=OPTIONS parsed arn =arn:aws:iam::123456789101:role/collectd-cloudwatch-putter
t=2017-05-03T20:18:31+0000 lvl=info msg=OPTIONS parsed duration=3600
t=2017-05-03T20:18:31+0000 lvl=info msg=OPTIONS parsed threshold=12
t=2017-05-03T20:18:31+0000 lvl=info msg=OPTIONS parsed between check duration=300
t=2017-05-03T20:18:31+0000 lvl=info msg=OPTIONS parsed daemon mode=false
t=2017-05-03T20:18:31+0000 lvl=info msg="Scanning credentials file..."
t=2017-05-03T20:18:31+0000 lvl=info msg="Got info from metadata service" instanceProfileArn=arn:aws:iam::987654321123:instance-profile/vESG-EC2 instanceProfileID=AIPAJGTJERYOLS33IW7OU
t=2017-05-03T20:18:31+0000 lvl=info msg="Response from AssumeRole" AccessKeyId=ASIAJ54PTDRCVBN7FU2A SecretAccessKey=VUCDe9LCup...(redacted) SessionToken=FQoDYXdzEMX//////////wEaDGSKSR...(redacted) Expiration="2017-05-03 21:18:34 +0000 UTC"
t=2017-05-03T20:18:31+0000 lvl=info msg="Wrote new credentials file." path=/root/.aws/credentials
```

If you run it again you'll notice it will only renew the token if it's less than your desired threshold to prevent unnecessary load on the STS API.
```
t=2017-05-03T20:20:03+0000 lvl=info msg="gossamer: assume-role via instance role" version=
t=2017-05-03T20:20:03+0000 lvl=info msg=OPTIONS parsed outfile=./gossamer_creds
t=2017-05-03T20:20:03+0000 lvl=info msg=OPTIONS parsed arn =arn:aws:iam::123456789101:role/collectd-cloudwatch-putter
t=2017-05-03T20:20:03+0000 lvl=info msg=OPTIONS parsed duration=3600
t=2017-05-03T20:20:03+0000 lvl=info msg=OPTIONS parsed threshold=12
t=2017-05-03T20:20:03+0000 lvl=info msg=OPTIONS parsed between check duration=300
t=2017-05-03T20:20:03+0000 lvl=info msg=OPTIONS parsed daemon mode=false
t=2017-05-03T20:20:03+0000 lvl=info msg="Scanning credentials file..."
t=2017-05-03T20:20:03+0000 lvl=info msg="Detected expiration string" TokenExpires="2017-05-03 21:18:34 +0000 UTC"
t=2017-05-03T20:20:03+0000 lvl=info msg="Token expiration check" ExpiresIn=58.515 renewThreshold=12.000
t=2017-05-03T20:20:03+0000 lvl=info msg="Token not yet expired. Exiting with no action."
```

Once that's build you can run a normal `aws` cli command like so and it will use the default credentials to perform the action in the other account.
```
aws --region us-east-1 cloudwatch put-metric-data --namespace collectd --value 80 --metric-name memory.percent.used --dimensions Host=blah2,PluginInstance=blah2
```

## Service
You can run as a service and make your own `init.d` script if you run in daemon mode. Push the JSON logfile wherever you wish.
```
$ sudo /usr/bin/gossamer -a arn:aws:iam::188894168332:role/collectd-cloudwatch-putter -t 12 -daemon &
[1] 9935
$
```

## Cron
If you want `gossamer` to run every 10 minutes you could set your `crontab -e` to something like this:
```
/10 * * * * /usr/bin/gossamer -o /root/.aws/credentials -a arn:aws:iam::123456789101:role/collectd-cloudwatch-putter -t 12 >> /var/log/gossamer.log
```

## Future Enhancements
* Systemd service or init.d script
* Makefile and install