#pragma once
#include "php.h"
#include "stdio.h"
#include "dirent.h"
#include "ext/standard/exec.h"
#include "SAPI.h"
#include "zend.h"
#include "zend_compile.h"
#include "zend_ini_scanner.h"
#include "zend_extensions.h"	// for zend_get_extension
#include "php_main.h"
#include "php_variables.h"
#include "php_ini.h"

#if (PHP_MAJOR_VERSION < 7)
#include "ext/standard/php_smart_str.h"
#else
#define UWSGI_PHP7
#endif
#include "ext/standard/info.h"

#include "ext/session/php_session.h"

#include <uwsgi.h>

#if ZEND_MODULE_API_NO >= 20190128
#ifndef TSRMLS_CC
#define TSRMLS_CC
#endif
#ifndef TSRMLS_C
#define TSRMLS_C
#endif
#ifndef TSRMLS_DC
#define TSRMLS_DC
#endif
#ifndef TSRMLS_D
#define TSRMLS_D
#endif
#endif

extern struct uwsgi_server uwsgi;
