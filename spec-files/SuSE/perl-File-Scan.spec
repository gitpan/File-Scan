%define class File
%define subclass Scan
%define _version 0.75
%define _release 1

# Derived values
%define module %{class}-%{subclass}
%define perlver %(rpm -q perl --queryformat '%%{version}' 2>/dev/null)
%define suse %(test -f /etc/SuSE-release && echo 1 || echo 0)

%define perlarchlib %(%{__perl} -V:installarchlib|%{__sed} "s/^.*='//;s/';$//")
%define perlprivlib %(%{__perl} -V:installprivlib|%{__sed} "s/^.*='//;s/';$//")

%if suse
%define suse_version %(grep VERSION /etc/SuSE-release|cut -f3 -d " ")
%define suse_version_short %(echo %{suse_version}|tr -d '.')
%define distro_release %{_release}suse%{suse_version_short}
%define distro_group Development/Languages/Perl
%else
%define distro_release %{_release}
%define distro_group Development/Perl
%endif

Summary:	Perl module %{class}::%{subclass} for scanning files for viruses
Summary(fr):	Module Perl %{class}::%{subclass} - détecteur de virus
Summary(de):	Perl-Modul %{class}::%{subclass} - Virus-Scanner
Name:		perl-%{module}
Version:	%{_version}
Release:	%{distro_release}
Group:		%{distro_group}
License:	GPL/Artistic License - see documentation
Vendor:		Henrique Dias <hdias@aesbuc.pt>
Packager:	Pascal Bleser <guru@unixtech.be>
Source:		http://www.cpan.org/modules/by-module/%{module}-%{version}.tar.gz
Url:		http://www.cpan.org/modules/by-module/%{class}
BuildRequires:	perl, make
BuildArch:	noarch
BuildRoot:	%{_tmppath}/build-%{name}-%{_version}-root/
Requires:	perl = %{perlver}
Provides:	%{module} = %{_version}
%if suse
Distribution:	SuSE Linux %{_suse_version}
%endif

%description
Perl module which implements the %{class}::%{subclass} class. 

%{class}::%{subclass} provides its own virus signature database.

You can use the "virusscan" script to scan files or directories
for viruses.

You can use the script "virus-procmail" to scan for infected
e-mails using procmail rules - have a look at
%{_docdir}/README.procmail
for further details.

The script "virus-update" can be used to download and install
the latest version of the %{class}::%{subclass} perl module
(must be root to do that).
Note that it won't update the RPM package but install the module
from the sources.

%description -l fr
Module Perl %{class}::%{subclass} pour détecter des virus.
Il dispose de sa propre base de données de signatures de virus.

Vous pouvez utiliser le script "virusscan" pour vérifier que des
fichiers ou des répertoires ne sont pas infectés.

Le script "virus-procmail" permet de vérifier si des e-mails
sont infectés à partir de règles procmail - lisez le fichier
%{_docdir}/README.procmail
pour plus de détails.

Le script "virus-update" peut être utilisé pour télécharger et
installer la dernière version du module Perl %{class}::%{subclass}
(vous devez être root).
Notez que ce script ne va pas effectuer une mise à jour du
paquetage RPM mais installer le module à partir des sources.

%description -l de
Diese Paket enthält das Perl-Modul %{class}::%{subclass} zum
Scannen nach Viren.
Es verfügt über eine eigene Virus-Signaturen-Datenbank.

Das Skript "virusscan" kann zum Suchen nach Viren in Dateien
oder Verzeichnissen verwendet werden.

Das "virus-procmail"-Skript kann aus procmail-Regeln heraus
nach Viren in E-Mails suchen - lesen Sie bitte die Datei
%{_docdir}/README.procmail
für nähere Informationen.

Das "virus-update"-Skript kann zum herunterladen und installieren
der letzten Version des Perl-Moduls %{class}::%{subclass} verwendet
werden (Sie müssen diese Skript als root aufrufen).
Es wird nicht dieses RPM-Paket aktualisieren sondern das Modul
anhand des Quellcodes installieren.

%prep
%setup -q -n %{module}-%{version}
%{__perl} Makefile.PL INSTALLDIRS=perl

%build
%{__make} OPTIMIZE="$RPM_OPT_FLAGS"

%install
%{__rm} -rf "${RPM_BUILD_ROOT}"

%{__mkdir_p} "${RPM_BUILD_ROOT}%{perlprivlib}"
%{__mkdir_p} "${RPM_BUILD_ROOT}%{perlarchlib}"

%{__make} install PREFIX="${RPM_BUILD_ROOT}%{_prefix}"

%if suse
#
# SuSE-specific handling of Perl modules
#
%{__mkdir_p} "${RPM_BUILD_ROOT}/var/adm/perl-modules"
%{__sed} "s@${RPM_BUILD_ROOT}@@g" \
         < "${RPM_BUILD_ROOT}%{perlarchlib}/perllocal.pod" \
         > "${RPM_BUILD_ROOT}/var/adm/perl-modules/%{_name}"

%endif

#
# Remove ${RPM_BUILD_ROOT} from .packlist file
#
packlist=`find "${RPM_BUILD_ROOT}%{perlarchlib}/" -name '.packlist' -type f`
if [ ! -f "$packlist" ]; then
         echo "*** ERROR: could not find .packlist :("
         exit 1
fi
%{__cp} "$packlist" "${packlist}.old"
%{__sed} "s@${RPM_BUILD_ROOT}@@g" < "${packlist}.old" \
| sort -u > "$packlist"
%{__rm} -f "${packlist}.old"

#
# Install additional example scripts
#
%{__mkdir_p} "${RPM_BUILD_ROOT}%{_bindir}"
%{__install} -m 755 examples/scan.pl "${RPM_BUILD_ROOT}%{_bindir}/virusscan"
%{__install} -m 755 examples/latest.pl "${RPM_BUILD_ROOT}%{_bindir}/virusupdate"
%{__install} -m 755 examples/procmail/scanvirus.pl "${RPM_BUILD_ROOT}%{_bindir}/virus-procmail"
# rename procmail-README to include it into the %doc section
%{__mv} examples/procmail/README README.procmail

%clean
%{__rm} -rf "${RPM_BUILD_ROOT}"

%files
%defattr(-,root,root)
%doc Changes README TODO docs/* README.procmail
%{_bindir}/*
%doc %{_mandir}/man*/*
%{perlprivlib}/%{class}/%{subclass}.pm
%dir %{perlarchlib}/auto/File/Scan
%{perlarchlib}/auto/File/Scan/.packlist
%if suse
/var/adm/perl-modules/%{_name}
%endif

%post
%if suse
/sbin/SuSEconfig --quick --module perl
%endif

%changelog
* Wed Nov 19 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.75
* Sat Nov 15 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.74
* Tue Nov 04 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.73
* Tue Nov 04 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.72
* Mon Nov 03 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.71
* Mon Nov 03 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.70
* Fri Oct 10 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.69
* Tue Sep 30 2003 Henrique Dias <hdias@aesbuc.pt> 
- Updated to 0.68
* Mon Sep 29 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.67
* Fri Sep 19 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.66
* Tue Sep 09 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.65
* Tue Sep 02 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.64
* Tue Aug 19 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.63
* Mon Aug 09 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.62
* Mon Aug 04 2003 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.61
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
* Sat Dec 28 2002 Henrique Dias <hdias@aesbuc.pt>
- Updated to 0.39
* Fri Nov 12 2002 Henrique Dias <hdias@esb.ucp.pt>
- Updated to 0.38
- fixed a small bug in spec-file
* Fri Oct 02 2002 Pascal Bleser <guru@unixtech.be>
- Updated to 0.37
- Use of __-macros everywhere
- Ported to SuSE: autodetects if built on SuSE Linux, should work on any distro
- Moved perl Makefile.PL into setup section
- Added installation of additional scripts
- Added french and german translations
- Changed many other things to make them cleaner
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
