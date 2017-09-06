Name: libbnxtre
Version: 20.6.1.2
Release: _PARAM_RELEASE%{?dist}
Summary: Userspace Library for Broadcom ROCE Device.
Group: System Environment/Libraries
License: GPL/BSD
Url: http://www.openfabrics.org/
Source: http://www.openfabrics.org/downloads/bnxtre/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: libibverbs-devel

%description
libbnxtre provides a device-specific userspace driver for Broadcom Netxtreme RoCE Adapters
for use with the libibverbs library.

%package devel
Summary: Development files for the libbnxtre driver
Group: System Environment/Libraries
Requires: %{name} = %{version}-%{release}

%description devel
Static version of libbnxtre that may be linked directly to an
application, which may be useful for debugging.

%prep
%setup -q -n %{name}-%{version}

%build
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall
# remove unpackaged files from the buildroot
rm -f $RPM_BUILD_ROOT%{_libdir}/*.la

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%{_libdir}/libbnxtre*.so
# %doc AUTHORS COPYING ChangeLog README
%config %{_sysconfdir}/libibverbs.d/bnxtre.driver

%files devel
%defattr(-,root,root,-)
%{_libdir}/libbnxtre*.a

%changelog
