%global debug_package %{nil}

Name:           sockcast-server
Version:        0.1.0
Release:        1%{?dist}
Summary:        Stateless Active-Active Coordinator Server for Sockcast Roaming SSH Agent
License:        MIT OR Apache-2.0
URL:            https://github.com/theraphim/sockcast-server
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang
BuildRequires:  systemd-rpm-macros
Requires:       systemd

%description
Sockcast Coordinator Server (sockcast-server) routes out-of-band SSH agent
identities and cryptographically signed SignRequests between remote Linux
hosts (sockcast-relay) and user workstations (sockcast-client) over HTTP/2
(h2c behind Nginx/Cloudflare or native TLS) with fast 1.5s SignAck failover.

%prep
%autosetup -n %{name}-%{version}

%build
go build -mod=vendor -trimpath -ldflags="-s -w" -o sockcast-server ./cmd/sockcast-server

%check
go test -mod=vendor ./...

%install
install -D -m 0755 sockcast-server %{buildroot}%{_bindir}/sockcast-server
install -D -m 0644 systemd/sockcast-server.service %{buildroot}%{_unitdir}/sockcast-server.service
install -D -m 0640 systemd/server.toml %{buildroot}%{_sysconfdir}/sockcast/server.toml

%post
%systemd_post sockcast-server.service

%preun
%systemd_preun sockcast-server.service

%postun
%systemd_postun_with_restart sockcast-server.service

%files
%doc README.md
%{_bindir}/sockcast-server
%{_unitdir}/sockcast-server.service
%dir %attr(0750,root,root) %{_sysconfdir}/sockcast
%config(noreplace) %{_sysconfdir}/sockcast/server.toml

%changelog
* Sun Nov 08 2026 Paul Komkoff <i@stingr.net> - 0.1.0-1
- Initial Fedora RPM package for sockcast-server
