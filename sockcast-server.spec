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
go build -mod=readonly -trimpath -ldflags="-s -w" -o sockcast-server ./cmd/sockcast-server

%check
go test -mod=readonly ./...

%install
install -D -m 0755 sockcast-server %{buildroot}%{_bindir}/sockcast-server
install -D -m 0644 systemd/sockcast-server.service %{buildroot}%{_unitdir}/sockcast-server.service
install -D -m 0644 systemd/sockcast-server.socket %{buildroot}%{_unitdir}/sockcast-server.socket
install -D -m 0644 systemd/sockcast-server-tcp@.socket %{buildroot}%{_unitdir}/sockcast-server-tcp@.socket
install -D -m 0644 systemd/server.toml %{buildroot}%{_sysconfdir}/sockcast/server.toml

%post
chmod 0755 %{_sysconfdir}/sockcast 2>/dev/null || :
chmod 0644 %{_sysconfdir}/sockcast/server.toml 2>/dev/null || :
%systemd_post sockcast-server.socket sockcast-server.service

%preun
%systemd_preun sockcast-server.socket sockcast-server.service

%postun
%systemd_postun_with_restart sockcast-server.socket sockcast-server.service

%files
%doc README.md
%{_bindir}/sockcast-server
%{_unitdir}/sockcast-server.service
%{_unitdir}/sockcast-server.socket
%{_unitdir}/sockcast-server-tcp@.socket
%dir %attr(0755,root,root) %{_sysconfdir}/sockcast
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sockcast/server.toml

%changelog
* Sun Nov 08 2026 Paul Komkoff <i@stingr.net> - 0.1.0-1
- Initial Fedora RPM package for sockcast-server
