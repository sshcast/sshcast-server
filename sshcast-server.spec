%global debug_package %{nil}

Name:           sshcast-server
Version:        0.1.0
Release:        1%{?dist}
Summary:        Stateless Active-Active Coordinator Server for Sshcast Roaming SSH Agent
License:        MIT OR Apache-2.0
URL:            https://github.com/sshcast/sshcast-server
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  golang
BuildRequires:  systemd-rpm-macros
Requires:       systemd

%description
Sshcast Coordinator Server (sshcast-server) routes out-of-band SSH agent
identities and cryptographically signed SignRequests between remote Linux
hosts (sshcast-relay) and user workstations (sshcast-client) over HTTP/2
(h2c behind Nginx/Cloudflare or native TLS) with fast 1.5s SignAck failover.

%prep
%autosetup -n %{name}-%{version}

%build
export GOWORK=off
GO_MOD_MODE="-mod=readonly"
if [ -d vendor ]; then
    GO_MOD_MODE="-mod=vendor"
fi
go build ${GO_MOD_MODE} -trimpath -ldflags="-s -w" -o sshcast-server ./cmd/sshcast-server

%check
export GOWORK=off
GO_MOD_MODE="-mod=readonly"
if [ -d vendor ]; then
    GO_MOD_MODE="-mod=vendor"
fi
go test ${GO_MOD_MODE} ./...

%install
install -D -m 0755 sshcast-server %{buildroot}%{_bindir}/sshcast-server
install -D -m 0644 systemd/sshcast-server.service %{buildroot}%{_unitdir}/sshcast-server.service
install -D -m 0644 systemd/sshcast-server.socket %{buildroot}%{_unitdir}/sshcast-server.socket
install -D -m 0644 systemd/sshcast-server-tcp@.socket %{buildroot}%{_unitdir}/sshcast-server-tcp@.socket
install -D -m 0644 systemd/server.toml %{buildroot}%{_sysconfdir}/sshcast/server.toml

%post
%systemd_post sshcast-server.socket sshcast-server.service

%preun
%systemd_preun sshcast-server.socket sshcast-server.service

%postun
%systemd_postun_with_restart sshcast-server.socket sshcast-server.service

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md
%{_bindir}/sshcast-server
%{_unitdir}/sshcast-server.service
%{_unitdir}/sshcast-server.socket
%{_unitdir}/sshcast-server-tcp@.socket
%dir %attr(0755,root,root) %{_sysconfdir}/sshcast
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/sshcast/server.toml

%changelog
* Sun Nov 08 2026 Paul Komkoff <i@stingr.net> - 0.1.0-1
- Initial Fedora RPM package for sshcast-server
