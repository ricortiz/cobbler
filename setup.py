#!/usr/bin/env python
import os, sys, time, yaml
import glob as _glob
from distutils.core import setup, Command
from distutils.command.install import install as _install
from distutils.command.build_py import build_py as _build_py
from distutils import log
import unittest
import exceptions
import pwd
import types
import shutil

try:
    import subprocess
except:
    import cobbler.sub_process as subprocess

try:
    import coverage
except:
    converage = None

VERSION = "2.5.0"
OUTPUT_DIR = "config"


#####################################################################
## Helper Functions #################################################
#####################################################################

def glob(*args, **kwargs):
    recursive = kwargs.get('recursive', False)
    results = []
    for arg in args:
        for elem in _glob.glob(arg):
            # Now check if we should handle/check those results.
            if os.path.isdir(elem):
                if os.path.islink(elem):
                    # We skip symlinks
                    pass
                else:
                    # We only handle directories if recursive was specified
                    if recursive == True:
                        results.extend(
                            # Add the basename of arg (the pattern) to elem and continue
                            glob(
                                os.path.join(elem, os.path.basename(arg)),
                                recursive=True))
            else:
                # Always append normal files
                results.append(elem)
    return results

#####################################################################

def gen_manpages():
    """Generate the man pages... this is currently done through POD,
    possible future version may do this through some Python mechanism
    (maybe conversion from ReStructured Text (.rst))...
    """

    manpages = {
        "cobbler":          'pod2man --center="cobbler" --release="" ./docs/cobbler.pod | gzip -c > ./docs/cobbler.1.gz',
        "koan":             'pod2man --center="koan" --release="" ./docs/koan.pod | gzip -c > ./docs/koan.1.gz',
        "cobbler-register": 'pod2man --center="cobbler-register" --release="" ./docs/cobbler-register.pod | gzip -c > ./docs/cobbler-register.1.gz',
    }

    #Actually build them
    for man, cmd in manpages.items():
        print("building %s man page." % man)
        if os.system(cmd):
            print "Creation of %s manpage failed." % man
            exit(1)

#####################################################################

def gen_build_version():
    fd = open(os.path.join(OUTPUT_DIR, "version"),"w+")
    gitdate = "?"
    gitstamp = "?"
    builddate = time.asctime()
    if os.path.exists(".git"):
       # for builds coming from git, include the date of the last commit
       cmd = subprocess.Popen(["/usr/bin/git","log","--format=%h%n%ad","-1"],stdout=subprocess.PIPE)
       data = cmd.communicate()[0].strip()
       if cmd.returncode == 0:
           gitstamp, gitdate = data.split("\n")
    data = {
       "gitdate" : gitdate,
       "gitstamp"      : gitstamp,
       "builddate"     : builddate,
       "version"       : VERSION,
       "version_tuple" : [ int(x) for x in VERSION.split(".")]
    }
    fd.write(yaml.dump(data))
    fd.close()

#####################################################################


#####################################################################
## Modify Build Stage  ##############################################
#####################################################################

class build_py(_build_py):
    """Specialized Python source builder."""

    def run(self):
        gen_manpages()
        gen_build_version()
        _build_py.run(self)

#####################################################################
## Modify Install Stage  ############################################
#####################################################################

class install(_install):
    """Specialised python package installer.

    It does some required chown calls in addition to the usual stuff.
    """

    def __init__(self, *args):
        _install.__init__(self, *args)

    def change_owner(self, path, owner):
        user = pwd.getpwnam(owner)
        try:
            log.info("changing mode of %s" % path)
            if not self.dry_run:
                # os.walk does not include the toplevel directory
                os.lchown(path, user.pw_uid, -1)
                # Now walk the directory and change them all
                for root, dirs, files in os.walk(path):
                    for dirname in dirs:
                        os.lchown(os.path.join(root, dirname), user.pw_uid, -1)
                    for filename in files:
                        os.lchown(os.path.join(root, filename), user.pw_uid, -1)
        except exceptions.OSError as e:
            # We only check for errno = 1 (EPERM) here because its kinda
            # expected when installing as a non root user.
            if e.errno == 1:
                self.warn("Could not change owner: You have insufficient permissions.")
            else:
                raise e

    def run(self):
        # Run the usual stuff.
        _install.run(self)

        # Hand over some directories to the webserver user
        self.change_owner(
            os.path.join(self.install_data, 'share/cobbler/web'),
            http_user)
        if not os.path.abspath(libpath):
            # The next line only works for absolute libpath
            raise Exception("libpath is not absolute.")
        self.change_owner(
            os.path.join(self.root + libpath, 'webui_sessions'),
            http_user)


#####################################################################
## Test Command #####################################################
#####################################################################

class test_command(Command):
    user_options = []

    def initialize_options(self):
        pass
    def finalize_options(self):
        pass

    def run(self):
        testfiles = []
        testdirs = ["koan"]

        for d in testdirs:
            testdir = os.path.join(os.getcwd(), "tests", d)

            for t in _glob.glob(os.path.join(testdir, '*.py')):
                if t.endswith('__init__.py'):
                    continue
                testfile = '.'.join(['tests', d,
                                     os.path.splitext(os.path.basename(t))[0]])
                testfiles.append(testfile)

        tests = unittest.TestLoader().loadTestsFromNames(testfiles)
        runner = unittest.TextTestRunner(verbosity = 1)

        if coverage:
            coverage.erase()
            coverage.start()

        result = runner.run(tests)

        if coverage:
            coverage.stop()
        sys.exit(int(bool(len(result.failures) > 0 or
                          len(result.errors) > 0)))

#####################################################################
## state command base class #########################################
#####################################################################

class statebase(Command):

    user_options = [
        ('statepath=', None, 'directory to backup configuration'),
        ('root=',      None, 'install everything relative to this alternate root directory')
        ]

    def initialize_options(self):
        self.statepath = statepath
        self.root = None

    def finalize_options(self):
        pass

    def _copy(self, frm, to):
        if os.path.isdir(frm):
            to = os.path.join(to, os.path.basename(frm))
            self.announce("copying %s/ to %s/" % (frm, to), log.DEBUG)
            if not self.dry_run:
                if os.path.exists(to):
                    shutil.rmtree(to)
                shutil.copytree(frm, to)
        else:
            self.announce("copying %s to %s" % (frm, os.path.join(to, os.path.basename(frm))), log.DEBUG)
            if not self.dry_run:
                shutil.copy2(frm, to)

#####################################################################
## restorestate command #############################################
#####################################################################

class restorestate(statebase):

    def _copy(self, frm, to):
        if self.root:
            to = self.root + to
        statebase._copy(self, frm, to)

    def run(self):
        self.announce("restoring the current configuration from %s" % self.statepath, log.INFO)
        if not os.path.exists(self.statepath):
            self.warn("%s does not exist. Skipping" % self.statepath)
            return
        self._copy(os.path.join(self.statepath, 'config'), libpath)
        self._copy(os.path.join(self.statepath, 'cobbler_web.conf'), webconfig)
        self._copy(os.path.join(self.statepath, 'cobbler.conf'), webconfig)
        self._copy(os.path.join(self.statepath, 'modules.conf'), etcpath)
        self._copy(os.path.join(self.statepath, 'settings'), etcpath)
        self._copy(os.path.join(self.statepath, 'users.conf'), etcpath)
        self._copy(os.path.join(self.statepath, 'users.digest'), etcpath)
        self._copy(os.path.join(self.statepath, 'dhcp.template'), etcpath)
        self._copy(os.path.join(self.statepath, 'rsync.template'), etcpath)

#####################################################################
## savestate command ################################################
#####################################################################

class savestate(statebase):

    description = "Backup the current configuration to /tmp/cobbler_settings."

    def _copy(self, frm, to):
        if self.root:
            frm = self.root + frm
        statebase._copy(self, frm, to)

    def run(self):
        self.announce( "backing up the current configuration to %s" % self.statepath, log.INFO)
        if os.path.exists(self.statepath):
            self.announce("deleting existing %s" % self.statepath, log.DEBUG)
            if not self.dry_run:
                shutil.rmtree(self.statepath)
        if not self.dry_run:
            os.makedirs(self.statepath)
        self._copy(os.path.join(libpath, 'config'), self.statepath)
        self._copy(os.path.join(webconfig, 'cobbler_web.conf'), self.statepath)
        self._copy(os.path.join(webconfig, 'cobbler.conf'), self.statepath)
        self._copy(os.path.join(etcpath, 'modules.conf'), self.statepath)
        self._copy(os.path.join(etcpath, 'settings'), self.statepath)
        self._copy(os.path.join(etcpath, 'users.conf'), self.statepath)
        self._copy(os.path.join(etcpath, 'users.digest'), self.statepath)
        self._copy(os.path.join(etcpath, 'dhcp.template'), self.statepath)
        self._copy(os.path.join(etcpath, 'rsync.template'), self.statepath)





#####################################################################
## Actual Setup.py Script ###########################################
#####################################################################
if __name__ == "__main__":
    ## Configurable installation roots for various data files.

    # Trailing slashes on these vars is to allow for easy
    # later configuration of relative paths if desired.
    docpath     = "share/man/man1"
    etcpath     = "/etc/cobbler/"
    initpath    = "/etc/init.d/"
    libpath     = "/var/lib/cobbler/"
    logpath     = "/var/log/"
    statepath   = "/tmp/cobbler_settings/devinstall"

    if os.path.exists("/etc/SuSE-release"):
        webconfig  = "/etc/apache2/conf.d"
        webroot     = "/srv/www/"
        http_user   = "wwwrun"
    elif os.path.exists("/etc/debian_version"):
        webconfig  = "/etc/apache2/conf.d"
        webroot     = "/srv/www/"
        http_user   = "www-data"
    else:
        webconfig  = "/etc/httpd/conf.d"
        webroot     = "/var/www/"
        http_user   = "apache"

    webcontent  = webroot + "cobbler_webui_content/"


    setup(
        cmdclass={
            'build_py': build_py,
            'test': test_command,
            'install': install,
            'savestate': savestate,
            'restorestate': restorestate
        },
        name = "cobbler",
        version = VERSION,
        description = "Network Boot and Update Server",
        long_description = "Cobbler is a network install server.  Cobbler supports PXE, virtualized installs, and reinstalling existing Linux machines.  The last two modes use a helper tool, 'koan', that integrates with cobbler.  There is also a web interface 'cobbler-web'.  Cobbler's advanced features include importing distributions from DVDs and rsync mirrors, kickstart templating, integrated yum mirroring, and built-in DHCP/DNS Management.  Cobbler has a XMLRPC API for integration with other applications.",
        author = "Team Cobbler",
        author_email = "cobbler@lists.fedorahosted.org",
        url = "http://www.cobblerd.org/",
        license = "GPLv2+",
        requires = [
            "mod_python",
            "cobbler",
        ],
        packages = [
            "cobbler",
            "cobbler/modules",
            "koan",
        ],
        package_dir = {
            "cobbler_web": "web/cobbler_web",
        },
        scripts = [
            "bin/cobbler",
            "bin/cobblerd",
            "bin/cobbler-ext-nodes",
            "bin/koan",
            "bin/ovz-install",
            "bin/cobbler-register",
        ],
        data_files = [
            # tftpd, hide in /usr/sbin
            ("sbin", ["bin/tftpd.py"]),

            ("%s" % webconfig,              ["config/cobbler.conf"]),
            ("%s" % webconfig,              ["config/cobbler_web.conf"]),
            ("%s" % initpath,               ["config/cobblerd"]),
            ("%s" % docpath,                glob("docs/*.gz")),
            ("share/cobbler/installer_templates",         glob("installer_templates/*")),
            ("%skickstarts" % libpath,      glob("kickstarts/*")),
            ("%ssnippets" % libpath,        glob("snippets/*", recursive=True)),
            ("%sscripts" % libpath,         glob("scripts/*")),
            ("%s" % libpath,                ["config/distro_signatures.json"]),
            ("share/cobbler/web",           glob("web/*.*")),
            ("%s" % webcontent,             glob("web/content/*.*")),
            ("share/cobbler/web/cobbler_web",             glob("web/cobbler_web/*.*")),
            ("share/cobbler/web/cobbler_web/templatetags",glob("web/cobbler_web/templatetags/*")),
            ("share/cobbler/web/cobbler_web/templates",   glob("web/cobbler_web/templates/*")),
            ("%swebui_sessions" % libpath,  []),
            ("%sloaders" % libpath,         []),
            ("%scobbler/aux" % webroot,     glob("aux/*")),

            #Configuration
            ("%s" % etcpath,                glob("config/*")),
            ("%s" % etcpath,                glob("templates/etc/*")),
            ("%siso" % etcpath,             glob("templates/iso/*")),
            ("%spxe" % etcpath,             glob("templates/pxe/*")),
            ("%sreporting" % etcpath,       glob("templates/reporting/*")),
            ("%spower" % etcpath,           glob("templates/power/*")),
            ("%sldap" % etcpath,            glob("templates/ldap/*")),

            #Build empty directories to hold triggers
            ("%striggers/add/distro/pre" % libpath,       []),
            ("%striggers/add/distro/post" % libpath,      []),
            ("%striggers/add/profile/pre" % libpath,      []),
            ("%striggers/add/profile/post" % libpath,     []),
            ("%striggers/add/system/pre" % libpath,       []),
            ("%striggers/add/system/post" % libpath,      []),
            ("%striggers/add/repo/pre" % libpath,         []),
            ("%striggers/add/repo/post" % libpath,        []),
            ("%striggers/add/mgmtclass/pre" % libpath,    []),
            ("%striggers/add/mgmtclass/post" % libpath,   []),
            ("%striggers/add/package/pre" % libpath,      []),
            ("%striggers/add/package/post" % libpath,     []),
            ("%striggers/add/file/pre" % libpath,         []),
            ("%striggers/add/file/post" % libpath,        []),
            ("%striggers/delete/distro/pre" % libpath,    []),
            ("%striggers/delete/distro/post" % libpath,   []),
            ("%striggers/delete/profile/pre" % libpath,   []),
            ("%striggers/delete/profile/post" % libpath,  []),
            ("%striggers/delete/system/pre" % libpath,    []),
            ("%striggers/delete/system/post" % libpath,   []),
            ("%striggers/delete/repo/pre" % libpath,      []),
            ("%striggers/delete/repo/post" % libpath,     []),
            ("%striggers/delete/mgmtclass/pre" % libpath, []),
            ("%striggers/delete/mgmtclass/post" % libpath,[]),
            ("%striggers/delete/package/pre" % libpath,   []),
            ("%striggers/delete/package/post" % libpath,  []),
            ("%striggers/delete/file/pre" % libpath,      []),
            ("%striggers/delete/file/post" % libpath,     []),
            ("%striggers/install/pre" % libpath,          []),
            ("%striggers/install/post" % libpath,         []),
            ("%striggers/install/firstboot" % libpath,    []),
            ("%striggers/sync/pre" % libpath,             []),
            ("%striggers/sync/post" % libpath,            []),
            ("%striggers/change" % libpath,               []),

            #Build empty directories to hold the database
            ("%sconfig" % libpath,               []),
            ("%sconfig/distros.d" % libpath,     []),
            ("%sconfig/images.d" % libpath,      []),
            ("%sconfig/profiles.d" % libpath,    []),
            ("%sconfig/repos.d" % libpath,       []),
            ("%sconfig/systems.d" % libpath,     []),
            ("%sconfig/mgmtclasses.d" % libpath, []),
            ("%sconfig/packages.d" % libpath,    []),
            ("%sconfig/files.d" % libpath,       []),

            #Build empty directories to hold koan localconfig
            ("/var/lib/koan/config",             []),

            # logfiles
            ("%scobbler/kicklog" % logpath,             []),
            ("%scobbler/syslog" % logpath,              []),
            ("%shttpd/cobbler" % logpath,               []),
            ("%scobbler/anamon" % logpath,              []),
            ("%skoan" % logpath,                        []),
            ("%scobbler/tasks" % logpath,               []),

            # spoolpaths
            ("share/cobbler/spool/koan",                []),

            # web page directories that we own
            ("%scobbler/localmirror" % webroot,         []),
            ("%scobbler/repo_mirror" % webroot,         []),
            ("%scobbler/ks_mirror" % webroot,           []),
            ("%scobbler/ks_mirror/config" % webroot,    []),
            ("%scobbler/links" % webroot,               []),
            ("%scobbler/aux" % webroot,                 []),
            ("%scobbler/pub" % webroot,                 []),
            ("%scobbler/rendered" % webroot,            []),
            ("%scobbler/images" % webroot,              []),

            #A script that isn't really data, wsgi script
            ("%scobbler/svc/" % webroot,     ["bin/services.py"]),

            # zone-specific templates directory
            ("%szone_templates" % etcpath,                []),
        ],
    )
