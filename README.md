![Alt text](gossamer.jpg?raw=true "gossamer")

# gossamer
CLI app to help you manage assuming roles across AWS accounts.

Two primary use cases:
* Can use a JSON list of ARNs and an MFA token to build assumed-role temporary credentials for roles in dozens of other accounts. 
* Can run as a service to continuously build aws credentials file with sts assume-role token based on the instance profile.
** For example you can use an instance profile role to assume-role in another AWS account.



## Modes

### profile-only
Sample command:
```
./gossamer -a arn:aws:iam::123456789101:role/collectd-cloudwatch-putter -entryname collectd-cloudwatch-putter -t 12 -o /tmp/creds
```
Builds your `/tmp/creds` file to look like this based on your current EC2 instance profile
```
[collectd-cloudwatch-putter]
# DO NOT EDIT
# GOSSAMER MANAGED SECTION
# (Will be overwritten regularly)
####################################################
# ASSUMED ROLE: arn:aws:iam::123456789101:role/collectd-cloudwatch-putter
# ASSUMED FROM INSTANCE ROLE: arn:aws:iam::987654321123:instance-profile/vESG-EC2
# GENERATED: 2017-05-17 22:12:14.163021505 +0000 UTC
# EXPIRES@2017-05-17 23:12:25 +0000 UTC
output = json
region = us-east-1
aws_access_key_id = ASIAIB123452NC2SX67
aws_secret_access_key = +3+AOLzPQnevergonnagiveyouupCrjsAV1fmDBwhlnUFsY
aws_session_token = FQoDYXdzEJ7//////////wEaDCN94Jg9dZc0Az7UWiLLAVfRnQiephwR+DrYFK9sFSxLa05B4dO3Ttw8CxHb/lhi1kEeZOa3DVhO1kg+I/ojgE4kKV0SETNc/hIqxa17nR2JnJU7WwxI6xunVppvqD+4n6RaV9wVSMJL7aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaGUoMgF

```


#### IAM Policy Prereqs Example
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

### mfa
The mfa mode lets you assume multiple roles using a seed starter profile and input list of json (see `rolesfile_sample.json`)

Sample Command:
```
./gossamer -o ~/.aws/credentials -rolesfile rolesfile_test.json -profile iam -serialnumber GADT99137836 -force -tokencode 123456
```
Where `iam` is the profile that will be loaded from `~/.aws/credentials` to then assume the roles listed in `rolesfile_test.json` using MFA token `123456` from device with serial number `GADT99137836`

Which will append to your `~/.aws/credentials file` the new entries. So that it looks like this:
```
1734021-C02RQ08ZG8WP:~ russellendicott$ cat ~/.aws/credentials
[iam]
output = json
region = us-east-1
aws_access_key_id = AKSDFFFFSDFSDFSDFSDFXYQ
aws_secret_access_key = dnreeeeeeeeeeeil/dhaZuasdf2LobN

[prod-account]
# DO NOT EDIT
# GOSSAMER MANAGED SECTION
# (Will be overwritten regularly)
####################################################
# ASSUMED ROLE: arn:aws:iam::123456789101:role/prod-role
# ASSUMED FROM INSTANCE ROLE: NA
# GENERATED: 2017-05-17 17:28:12.531306428 -0400 EDT
# EXPIRES@2017-05-17 22:28:11 +0000 UTC
output = json
region = us-east-1
aws_access_key_id = OIEOINVOINONVINOPNE
aws_secret_access_key = 23hx01imafakesak5QVutvPEg
aws_session_token = FbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtoken==

[dev-account]
# DO NOT EDIT
# GOSSAMER MANAGED SECTION
# (Will be overwritten regularly)
####################################################
# ASSUMED ROLE: arn:aws:iam::110987654321:role/dev-role
# ASSUMED FROM INSTANCE ROLE: NA
# GENERATED: 2017-05-17 17:28:12.614751011 -0400 EDT
# EXPIRES@2017-05-17 22:28:11 +0000 UTC
output = json
region = us-east-1
aws_access_key_id = ABAABABOIBOINSBOINS
aws_secret_access_key = /P8iimafakesakJPC5bqQHDoHO7Cwd6Vq
aws_session_token = FbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtokenFbiglongtoken==

```
## Build/Run from Source

```
go get github.com/aws/aws-sdk-go/aws/session
go get github.com/aws/aws-sdk-go/service/sts
go get github.com/aws/aws-sdk-go/aws
go get github.com/aws/aws-sdk-go/aws/ec2metadata
go get github.com/aws/aws-sdk-go/aws/credentials/ec2rolecreds
go get github.com/aws/aws-sdk-go/aws/credentials
go get github.com/inconshreveable/log15
go build -o ./build/gossamer -ldflags "-X main.version=v0.0.0"
sudo mv ./build/gossamer /usr/bin/gossamer
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
    	Duration of token in seconds. (min=900, max=3600)  (default 3600)
  -entryname string
    	when used with single ARN this is the entry name that will be added to the creds file (e.g., '[test-env]') (default "gossamer")
  -force
    	force refresh even if token not yet expired
  -logfile string
    	JSON logfile location (default "gossamer.log.json")
  -loglevel string
    	Log level (info or debug) (default "info")
  -o string
    	Output credentials file. (default "./gossamer_creds")
  -profile string
    	Cred file profile to use. This overrides the default of using instance role from metadata.
  -purgecreds
    	Purge managed entries from credentials file and exit
  -region string
    	Region mandatory in mfa and profile mode (default "us-east-1")
  -rolesfile string
    	File that contains json list of roles to assume and add to file.
  -s int
    	Duration in seconds to wait between checks. (default 300)
  -serialnumber string
    	Serial number of MFA device
  -t int
    	 threshold in minutes. (default 10)
  -tokencode string
    	Token code of mfa device.
  -v	print version and exit
```

Test the command like so using the assumeRole that is allowed per your instance profile:
```
sudo /usr/bin/gossamer -o /root/.aws/credentials -a arn:aws:iam::123456789101:role/collectd-cloudwatch-putter -t 12
```
You should see an output similar to the following:
```
t=2017-05-17T22:26:31+0000 lvl=info msg="gossamer: assume-role via instance role" version=0.0.2.12
t=2017-05-17T22:26:31+0000 lvl=info msg=OPTIONS parsed outfile=/root/.aws/credentials
t=2017-05-17T22:26:31+0000 lvl=info msg=OPTIONS parsed arn =arn:aws:iam::123456789101:role/collectd-cloudwatch-putter
t=2017-05-17T22:26:31+0000 lvl=info msg=OPTIONS parsed duration=3600
t=2017-05-17T22:26:31+0000 lvl=info msg=OPTIONS parsed threshold=12
t=2017-05-17T22:26:31+0000 lvl=info msg=OPTIONS parsed between check duration=300
t=2017-05-17T22:26:31+0000 lvl=info msg=OPTIONS parsed daemon mode=false
t=2017-05-17T22:26:31+0000 lvl=info msg=OPTIONS parsed profile=
t=2017-05-17T22:26:31+0000 lvl=info msg=OPTIONS parsed region=us-east-1
t=2017-05-17T22:26:31+0000 lvl=info msg=OPTIONS parsed serialNumber=
t=2017-05-17T22:26:31+0000 lvl=info msg=OPTIONS parsed tokenCode=
t=2017-05-17T22:26:31+0000 lvl=info msg=OPTIONS parsed forceRefresh=false
t=2017-05-17T22:26:31+0000 lvl=info msg=MODE determined mode=profile-only
t=2017-05-17T22:26:31+0000 lvl=info msg="Scanning credentials file..."
t=2017-05-17T22:26:31+0000 lvl=info msg="Detected expiration string" TokenExpires="2017-05-02 05:40:56 +0000 UTC"
t=2017-05-17T22:26:31+0000 lvl=info msg="Token expiration check" ExpiresIn=-22605.587 renewThreshold=12.000
t=2017-05-17T22:26:31+0000 lvl=info msg="Got info from metadata service" instanceProfileArn=arn:aws:iam::987654321123:instance-profile/vESG-EC2 instanceProfileID=ALKJOIVNOIENOAISNVOE
t=2017-05-17T22:26:31+0000 lvl=info msg="Response from AssumeRole" AccessKeyId=VOIANMAOIEONIIVIOE SecretAccessKey=7/a5xP6H2W...(redacted) SessionToken=FQoDYXHEHAHEE+IqK5EZOw62dRS...(redacted) Expiration="2017-05-17 23:26:42 +0000 UTC"
t=2017-05-17T22:26:31+0000 lvl=info msg="Wrote new credentials file." path=/root/.aws/credentials
```

If you run it again you'll notice it will only renew the token if it's less than your desired threshold to prevent unnecessary load on the STS API.
```
t=2017-05-17T22:30:03+0000 lvl=info msg="gossamer: assume-role via instance role" version=0.0.2.12
t=2017-05-17T22:30:03+0000 lvl=info msg=OPTIONS parsed outfile=/root/.aws/credentials
t=2017-05-17T22:30:03+0000 lvl=info msg=OPTIONS parsed arn =arn:aws:iam::123456789101:role/collectd-cloudwatch-putter
t=2017-05-17T22:30:03+0000 lvl=info msg=OPTIONS parsed duration=3600
t=2017-05-17T22:30:03+0000 lvl=info msg=OPTIONS parsed threshold=12
t=2017-05-17T22:30:03+0000 lvl=info msg=OPTIONS parsed between check duration=300
t=2017-05-17T22:30:03+0000 lvl=info msg=OPTIONS parsed daemon mode=false
t=2017-05-17T22:30:03+0000 lvl=info msg=OPTIONS parsed profile=
t=2017-05-17T22:30:03+0000 lvl=info msg=OPTIONS parsed region=us-east-1
t=2017-05-17T22:30:03+0000 lvl=info msg=OPTIONS parsed serialNumber=
t=2017-05-17T22:30:03+0000 lvl=info msg=OPTIONS parsed tokenCode=
t=2017-05-17T22:30:03+0000 lvl=info msg=OPTIONS parsed forceRefresh=false
t=2017-05-17T22:30:03+0000 lvl=info msg=MODE determined mode=profile-only
t=2017-05-17T22:30:03+0000 lvl=info msg="Scanning credentials file..."
t=2017-05-17T22:30:03+0000 lvl=info msg="Detected expiration string" TokenExpires="2017-05-17 23:30:12 +0000 UTC"
t=2017-05-17T22:30:03+0000 lvl=info msg="Token expiration check" ExpiresIn=60.136 renewThreshold=12.000
t=2017-05-17T22:30:03+0000 lvl=info msg="Token not yet expired. Exiting with no action."
```

Once that's build you can run a normal `aws` cli command like so and it will use the default credentials to perform the action in the other account.
```
aws --profile gossamer --region us-east-1 cloudwatch put-metric-data --namespace collectd --value 80 --metric-name memory.percent.used --dimensions Host=blah2,PluginInstance=blah2
```

## Service
You can run as a service and make your own `init.d` script if you run in daemon mode. Push the JSON logfile wherever you wish.
```
$ sudo /usr/bin/gossamer -a arn:aws:iam::123456789101:role/collectd-cloudwatch-putter -t 12 -daemon &
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
