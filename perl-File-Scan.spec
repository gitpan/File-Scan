%define class File
%define subclass Scan
%define version 0.26
%define release 1

# Derived values
%define real_name %{class}-%{subclass}
%define name perl-%{real_name}

Summary: 	Perl module %{class}::%{subclass}
Name: 		%{name}
Version: 	%{version}
Release: 	%{release}
Group: 		Development/Perl
License:        See documentation
Source: 	http://www.cpan.org/modules/by-module/%{class}/%{real_name}-%{version}.tar.gz
Url: 		http://www.cpan.org/modules/by-module/%{class}
Packager:       Michael McLagan <Michael.McLagan@linux.org>
BuildRequires:	perl >= 5.6.1
BuildArch: 	noarch
BuildRoot: 	%{_tmppath}/%{name}-root/
Requires: 	perl >= 5.6.1

%description
Perl module which implements the %{class}::%{subclass} class.  

%prep
%setup -q -n %{real_name}-%{version}

%build
%{__perl} Makefile.PL
make OPTIMIZE="$RPM_OPT_FLAGS"

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall PREFIX=$RPM_BUILD_ROOT%{_prefix}

# Install the example scan program as virusscan
mkdir -p $RPM_BUILD_ROOT%{_bindir}
install -m 755 examples/scan.pl $RPM_BUILD_ROOT%{_bindir}/virusscan

# Clean up some files we don't want/need
rm -rf `find $RPM_BUILD_ROOT -name "perllocal.pod"`
rm -rf `find $RPM_BUILD_ROOT -name ".packlist" -o -name "*.bs"`

# Remove all empty directories
for i in `find $RPM_BUILD_ROOT -type d | tac`; do
   if [ -d $i ]; then 
      rmdir --ign -p $i;
   fi
done

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
* Mon May 14 2002 Michael McLagan  <michael.mclagan@linux.org>
- Updated to 0.26
* Sun May 05 2002 Michael McLagan  <michael.mclagan@linux.org>
- Updated to 0.25
  Fixed a couple of items in spec file
* Tue Apr 30 2002 Michael McLagan <michael.mclagan@linux.org>
- initial version 0.24
