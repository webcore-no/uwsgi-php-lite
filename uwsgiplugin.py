import os



ld_run_path = None
PHPPATH = 'php-config'

phpdir = os.environ.get('UWSGICONFIG_PHPDIR')
if phpdir:
    ld_run_path = "%s/lib" % phpdir
    PHPPATH = "%s/bin/php-config" % phpdir

PHPPATH = os.environ.get('UWSGICONFIG_PHPPATH', PHPPATH)

verinfo = os.popen(PHPPATH + ' --version').read().rstrip().split('.')
major = verinfo[0]
minor = verinfo[1]
patch = verinfo[2]

NAME = 'php_lite_'+major+'_'+minor+'_'+patch

CFLAGS = [os.popen(PHPPATH + ' --includes').read().rstrip(), '-Wno-sign-compare','-DPHPNAME="'+NAME+'_plugin"']
LDFLAGS = os.popen(PHPPATH + ' --ldflags').read().rstrip().split()

if ld_run_path:
    LDFLAGS.append('-L%s' % ld_run_path)
    os.environ['LD_RUN_PATH'] = ld_run_path

LIBS = [os.popen(PHPPATH + ' --libs').read().rstrip(), '-lphp' + major]

phplibdir = os.environ.get('UWSGICONFIG_PHPLIBDIR')
if phplibdir:
    LIBS.append('-flto=thin -Wl,-rpath,%s' % phplibdir)

GCC_LIST = [ 'php_lite_plugin','session', 'php_cache_module']
