Name:           gossamer
Version:        1.2.2.56
Release:        0
Summary:        CLI app and daemon for constantly generating assume-role credentials.
Group:          System Environment/Daemons
License:        MIT 
URL:            https://github.com/rendicott/%{name}
Vendor:         NA
Source:         https://github.com/rendicott/%{name}/releases/download/v%{version}/%{name}-linux-amd64-%{version}.tar.gz
Prefix:         %{_prefix}
Packager: 	Russell Endicott
BuildRoot:      %{_tmppath}/%{name}-root

%description
CLI app to help you manage assuming roles across AWS accounts. Two primary use cases: Can use a JSON list of ARNs and an MFA token to build assumed-role temporary credentials for roles in dozens of other accounts or it can run as a service to continuously build aws credentials file with sts assume-role token based on the instance profile. For example you can use an instance profile role to assume-role in another AWS account.



%prep
%setup -q -n %{name}-linux-amd64-%{version}.tar.gz


%build
%configure



%install
pwd

%files
%doc



%changelog

