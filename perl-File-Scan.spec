%define class File
%define subclass Scan
%define version 0.35
%define release 1

# Derived values
%define module %{class}-%{subclass}
%define perlver %(rpm -q perl --queryformat '%%{version}' 2>/dev/null)

Summary:	Perl module %{class}::%{subclass}
Name:		perl-%{module}
Version:	%{version}
Release:	%{release}
Group:		Development/Perl
License:	See documentation
Vendor:		Henrique Dias <hdias@esb.ucp.pt>
Source:		http://www.cpan.org/modules/by-module/%{module}-%{version}.tar.gz
Url:		http://www.cpan.org/modules/by-module/%{class}
BuildRequires:	perl
BuildArch:	noarch
BuildRoot:	%{_tmppath}/%{name}-root/
Requires:	perl = %{perlver}
Provides:	%{module} = %{version}

%description
Perl module which implements the %{class}::%{subclass} class. 

%prep
%setup -q -n %{module}-%{version}

%build
%{__perl} Makefile.PL
%{__make} OPTIMIZE="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall PREFIX=$RPM_BUILD_ROOT%{_prefix}

# Install the example scan program as virusscan
mkdir -p $RPM_BUILD_ROOT%{_bindir}
install -m 755 examples/scan.pl $RPM_BUILD_ROOT%{_bindir}/virusscan

# Clean up some files we don't want/need
rm -rf `find $RPM_BUILD_ROOT -name "perllocal.pod" -o \
		-name ".packlist" -o \
		-name "*.bs"`

# Remove all empty directories
find $RPM_BUILD_ROOT%{_prefix} -type d | tac | xargs rmdir --ign

%clean
HERE=`pwd`
cd ..
rm -rf $HERE
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc Changes README TODO docs/write_sign_bin.txt
%{_prefix}

%changelog
* Fri Aug 30 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.35
* Mon Jul 22 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.34
* Tue Jul 15 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.33
* Tue Jul 08 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.32
* Tue Jun 25 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.31
* Tue Jun 17 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.30
* Mon Jun 03 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.29
* Mon May 27 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.28
* Sat May 20 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.27
* Mon May 14 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.26
  Inserted code to adapt to perl version
  Replaced real_name macro with module
* Sun May 05 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.25
  Fixed a couple of items in spec file
* Tue Apr 30 2002 Michael McLagan <michael.mclagan@linux.org>
- initial version 0.24
