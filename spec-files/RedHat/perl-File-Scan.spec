%define class File
%define subclass Scan
%define version 0.60
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
Vendor:		Henrique Dias <hdias@aesbuc.pt>
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
* Mon Jul 28 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.60
* Mon Jul 01 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.59
* Fri Jun 26 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.58
* Fri Jun 20 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.57
* Thu Jun 05 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.56
* Mon Jun 02 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.55
* Tue May 20 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.54
* Fri May 16 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.53
* Wed May 14 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.52
* Sat Apr 26 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.51
* Wed Apr 23 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.50
* Tue Apr 22 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.49
* Fri Apr 11 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.48
* Wed Apr 09 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.47
* Tue Apr 08 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.46
* Sat Mar 29 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.45
* Sat Mar 15 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.44
* Mon Jan 13 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.43
* Fri Jan 10 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.42
* Thu Jan 09 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.41
* Sat Jan 04 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.40
* Sat Dec 28 2002 Henrique Dias <hdias@esb.ucp.pt>
- Updated to 0.39
* Tue Nov 12 2002 Henrique Dias <hdias@esb.ucp.pt>
- Updated to 0.38
* Fri Oct 02 2002 Henrique Dias <hdias@esb.ucp.pt>
- Updated to 0.37
* Thu Sep 12 2002 Michael McLagan <michael.mclagan@linux.org>
- Updated to 0.36
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
