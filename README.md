[![Build Status](https://travis-ci.org/GESkunkworks/gossamer.svg?branch=master)](https://travis-ci.org/GESkunkworks/gossamer)
[![Coverage Status](https://coveralls.io/repos/github/GESkunkworks/gossamer/badge.svg?branch=master)](https://coveralls.io/github/GESkunkworks/gossamer?branch=master)

[![gossamer image generated by gbprinter package](img/gossamer_grayscale.png?raw=true "gossamer")](https://github.com/ProfOak/gbprinter)

# gossamer
CLI app to help you manage assuming lots of roles across multiple AWS accounts and set them up as profile entries in an AWS credentials file.

Gossamer is good at a few things:
* Assume lots of roles from a set of starter credentials with MFA and multi credential chaining.
* Assume lots of roles from a SAML assertion and use those creds to assume other roles

It won't mess with your existing profile entries and will instead add/modify it's own entries.

Sample resulting profile entry:
```
[admin-role]
# DO NOT EDIT
# ACFMGR MANAGED SECTION
# (Will be overwritten regularly)
####################################################
# ASSUMED ROLE: arn:aws:iam::1234567899012:role/admin
# ASSUMED FROM INSTANCE ROLE: NA
# GENERATED: 2020-01-04 18:34:24.563761 +0000 UTC
# EXPIRES@   2020-01-04 19:34:23 +0000 UTC
# DESCRIPTION: classic
region = us-east-1
aws_access_key_id = ASISUDIWNEIVJUEWDF6RPF
aws_secret_access_key = Ttc8aalkasdnf3olaknoi23o2FLAQE9
aws_session_token = FwoGZXIvYXdzEPz//////////wEaaoiwenfawoifawpinawofinawapiuawapoeuiawfopiauoawiuefEIIEEaieiEIEOEOOoowoEOEEOEOogoEOEogoocNNNNenweOeienDnDndDDDDDDDDDDDDDDDDDDJDDDDDDDDDDDDDDDDDJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJjjjjjEEEEEEEEEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEeeasdofwoeifapuhviuabviUDUDUFBDUFBIUEBFIEUBIFUBEFZG2KG6HhrBqGfg5n7mk/URw=
```

From which you can run commands using the profile like
```
aws --profile admin-role iam list users
```


## Installation
On a mac you can do a Homebrew install.


```
brew tap GESkunkworks/gossamer https://github.com/GESkunkworks/geskunkworks-taps
brew install gossamer
```

For Windows and Linux you can grab one of the releases and unzip it to your desired location.

### Quick Start - SAML
Assumes you want to use a SAML login to assume all roles that come back from the SAML assertion.

Generate a sample config file using `./gossamer -generate @sample` and then modify the resulting file to look something like:

```yaml
output_file: "~/.aws/credentials"
flows:
- name: sample-saml
  saml_config:
    username:
      source: env
      value: SAML_USER
    password:
      source: prompt
    url:
      source: config
      value: https://my.saml.auth.url.com/auth.fcc
    target:
      source: config
      value: https://my.auth.target.com/fss/idp/startSSO.ping?PartnerSpId=urn:amazon:webservices
  primary_assumptions:
    all_roles: true
```

Obviously you'll need to update the URL and target parameters with whatever is necessary for your organization. 

Save the file as `config.yml` and run `gossamer -c config.yml`.

You'll be prompted to enter the value for the SAML password since you set the `password` parameter to be of source type `prompt`. After entering your password you should see gossamer attempt to assume all of the roles that come back in your SAML assertion since you set `all_roles: true` under `primary_assumptions`.

From there you should see a bunch of entries in `~/.aws/credentials` with auto generated profile names in the format `[<account_number>_<role_name>]`. If you want to give these a friendlier name you can add specific arn-to-profile name mappings to the mappings list.

From there you can use the entries with the AWS CLI running commands such as:
```
aws --profile 123456789012_admin ec2 describe-instances
```


### Quick Start - Permanent Credentials
Assumes you want to start with a local profile entry that has the permission--if logged in with MFA--to assume multiple additional roles.

First add your user's permanent keys to the `~/.aws/credentials` file with the profile name `[giam]` like so:

```
[giam]
output                = json
region                = us-east-1
aws_access_key_id     = AKILDOIAOFIFEFOEFSMA
aws_secret_access_key = KBhehehehehehenotgonnaguessmenowZW
```

Next, find out what the ARN or serial number of the same user's MFA device is that is associated with the above perm creds.

Generate a sample config file using `./gossamer -generate @sample` and then modify the resulting file to look something like:

```yaml
output_file: "~/.aws/credentials"
flows:
- name: sample-permanent-creds-mfa
  permanent:
    mfa:
      serial:
        source: config
        value: "GAKT0008D4BC"
      token:
        source: prompt
  primary_assumptions:
    mappings:
    - role_arn: arn:aws:iam::123456789012:role/sub-admin
      profile_name: sub-admin
      region: us-west-2
    - role_arn: arn:aws:iam::123456789012:role/role2
      profile_name: role2
```

Save the file as `config.yml` and then run `./gossamer -c config.yml`

From there it will prompt you for the token for the MFA device with serial number `GAKT0008D4BC` and if successful it will assume the two roles provided in the mappings list under primary assumptions.

You should see output that indicates the role assumptions were successful and your `~/.aws/credentials` file will have new entries. 

# Configuration Reference
Below is a sample configuration file YML with comments explaining each section. You can always generate your own sample using the `gossamer -generate @sample` command. 

```yaml
# the file to which the AWS profile entries will be written
output_file: ./path/to/credentials/file

# flows define authentication workflows. They can use different types of
#  starter credentials to get their primary assumptions (e.g., SAML or permanent)
#  from which secondary assumptions can be made with the primary assumptions 
#  as sponsors
flows:
  # name is a simple identifier for the flow and will be used in logging
  #  and will also be included in the resulting profile entry
- name: sample-permanent-creds-mfa
  # when the 'permanent' block is present gossamer will assume you want to
  #  run a flow using permament credentials. If no other  sub-parameters
  #  are present under permanent then it will try to use the normal auth
  #  flow provided by AWS (e.g., ENV vars, instance-profile, etc)
  permanent:
    # mfa section being present will force the starter creds to first
    #  get an mfa enabled session using the provided serial and token
    #  before attempting to assume roles in the primary assumptions
    mfa:
      serial:
        source: config # config means the value for this param comes from this config file in the below 'value'
        value: sampleserial # the value for the desired source (see more advanced in SAML section below)
      token:
        source: config
        value: sampletoken
  # primary_assumptions is what the starter creds (permament or SAML) will assume after
  #  the intial session is established using the above auth information for the flow.
  primary_assumptions:
    all_roles: false # in a permanent creds flow all_roles is ignored anyway
    # mappings are a list of roles to assume using the above starter creds
    mappings:
    - role_arn: arn:aws:iam::123456789012:role/role2 # the only mandatory field is a role_arn
    - role_arn: arn:aws:iam::123456789012:role/sub-adminu
      profile_name: sub-admin # the optional profile name to give this credential. If not provided one will be generated using the format '<account_number>_<rolename>'
      region: us-west-2 # this region will override any imnherited region from parent flow
      no_output: true # in case you don't want the creds written to the output file
  allow_failure: true # if no creds are generated during this flow gossamer will ignore and move to next flow
  do_not_propagate_region: false # in case you don't want to propagate the region down to the mappings from the flow's region
- name: sample-saml
  # saml_config when provided indicates to gossamer that you want to run a SAML flow
  saml_config:
    # username, password, url, and target are required parameters
    username:
      source: env # you can use keyword 'env' if you want to source this parameter from the value stored in the environment variable provided in the 'value' field. For example, here the value will be provided from $SAML_USER
      value: SAML_USER
    password:
      source: prompt # you can use the keyword 'prompt' if you want gossamer to pause and ask you for the value for this input parameter. You can use 'prompt' as the source for any parameter but when used for password the input is hidden
    url: # url is where your username, password, and target will be sent to
      source: config
      value: https://my.saml.auth.url.com/auth.fcc
    target: # target will be passed as a url param to the provided URL. This is crucial for some SAML providers such as Ping
      source: config
      value: https://my.auth.target.com/fss/idp/startSSO.ping?PartnerSpId=urn:amazon:webservices
  primary_assumptions:
    all_roles: true # in SAML flows you can request that all roles that can be assumed in the SAML assertion be assumed
    mappings: # when providing mappings when all_roles = true, all roles in the assertion will be assumed but the provided mappings will be given the additional metadata you specify. This is useful if you want to give user friendly names to the profile entries
    - role_arn: arn:aws:iam::123456789012:role/sub-admin
      profile_name: sub-admin
      region: us-west-2
      no_output: true
    - role_arn: arn:aws:iam::123456789012:role/role2
      profile_name: role2
  secondary_assumptions:
    all_roles: false # this is always ignored under secondary_assumptions
    # mappings under secondary assumptions will be assumed using one of the primary assumption credentials
    mappings:
    - role_arn: arn:aws:iam::123456789012:role/admin
      profile_name: admin
      region: us-west-2
      sponsor_creds_arn: arn:aws:iam::123456789012:role/sub-admin # if there are multiple primary assumptions then a sponsor_creds_arn is required in order to let gossamer know which primary credential to use to assume this secondary credential
  region: us-east-2
  allow_failure: false
  do_not_propagate_region: true
```

As many flows can be defined as desired by the user. For example, it may be useful to define multiple SAML flows for MFA enabled SAML providers and non MFA SAML providers as well as a few testing flows for permanent creds. 

# Running With No Config File
You can get some of the non-SAML functionality out of gossamer without ever having to make a config file. This is mostly here as legacy support for gossamer 1.x users' aliases but can be helpful for one off commands. 

We'll go over a few here but see the full list of parameters at the bottom of the README or by running `gossamer -help`. 

The following command will load roles to assume from a legacy "rolesfile" formatted JSON file and assume them using an MFA enabled session from the `giam` profile.
```
gossamer -o ./creds -rolesfile "./roles.json" -profile giam -serialnumber $MFA -tokencode 1234567
```

You can find a sample legacy rolesfile in the `./samples` directory but here's a quick reference:
```json
{
    "Roles": [{
        "RoleArn": "arn:aws:iam::123456789101:role/prod-role",
        "AccountName": "prod-account",
        "Region": "us-east-1"
    }, {
        "RoleArn": "arn:aws:iam::110987654321:role/dev-role",
        "AccountName": "dev-account",
        "Region": "us-west-1"
    }]
}
```

You can also just assume a single role without needing a config file. For example, in Windows the command would look something like:
```
gossamer -o %HOMEPATH%\.aws\credentials -a arn:aws:iam::8765448765487:role/sadmin -profile default -serialnumber arn:aws:iam::876548765487:mfa/rendicott -tokencode 123456
```

# gossamer 1.x Users
Users of previous versions of gossamer and probably not familiar with the concept of the config file and flows. The good news is that most of the 1.x command arguments are supported in 2.x except for the daemon mode functionality which has been removed. What this means is that most users can use their existing command aliases with the new version while they work on converting to the new config/flow flormat. 

Running your "legacy" gossamer command and adding the `-generate my-config.yml` parameter will translate your command arguments to a gossamer 2.x config file. 

## Build/Run from Source

```
go get ./...
go build -o ./build/gossamer -ldflags "-X main.version=v0.0.0"
sudo mv ./build/gossamer /usr/bin/gossamer
```

## Usage
Here's the output of the contextual `--help` flag:
```
```
