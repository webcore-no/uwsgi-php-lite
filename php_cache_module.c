#include "php_cache_module.h"


ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_version, 0)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_version) {
#ifdef UWSGI_PHP7
	RETURN_STRING(VEREDIS_QUE_VERSION);
#else
	RETURN_STRING(VEREDIS_QUE_VERSION, 1);
#endif
}

ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_setprocname, 0)
ZEND_ARG_INFO(0, name)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_setprocname) {

	char *name;
	int name_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "s", &name, &name_len) == FAILURE) {
		RETURN_NULL();
	}

	uwsgi_set_processname(estrndup(name, name_len));

	RETURN_NULL();
}

ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_worker_id, 0)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_worker_id) {
	RETURN_LONG(uwsgi.mywid);
}

ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_masterpid, 0)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_masterpid) {
	if (uwsgi.master_process) {
		RETURN_LONG(uwsgi.workers[0].pid);
	}
	RETURN_LONG(0);
}

ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_signal, 0)
ZEND_ARG_INFO(0, long_signum)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_signal) {

	long long_signum;
	uint8_t signum = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "l", &long_signum) == FAILURE) {
		RETURN_NULL();
	}

	signum = (uint8_t) long_signum;
	uwsgi_signal_send(uwsgi.signal_socket, signum);

	RETURN_NULL();
}

ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_rpc, 0)
ZEND_ARG_VARIADIC_INFO(0, varargs)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_rpc) {
	int num_args = 0;
	int i;
	char *node = NULL;
	char *func = NULL;
	zval ***varargs = NULL;
	zval *z_current_obj;
	char *argv[256];
	uint16_t argvs[256];
	uint64_t size = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "+", &varargs, &num_args) == FAILURE) {
		RETURN_NULL();
	}

	if (num_args < 2)
		goto clear;

	if (num_args > 256 + 2)
		goto clear;

	z_current_obj = *varargs[0];
	if (Z_TYPE_P(z_current_obj) != IS_STRING) {
		goto clear;
	}

	node = Z_STRVAL_P(z_current_obj);

	z_current_obj = *varargs[1];
	if (Z_TYPE_P(z_current_obj) != IS_STRING) {
		goto clear;
	}

	func = Z_STRVAL_P(z_current_obj);

	for (i = 0; i < (num_args - 2); i++) {
		z_current_obj = *varargs[i + 2];
		if (Z_TYPE_P(z_current_obj) != IS_STRING) {
			goto clear;
		}
		argv[i] = Z_STRVAL_P(z_current_obj);
		argvs[i] = Z_STRLEN_P(z_current_obj);
	}

	// response must always be freed
	char *response = uwsgi_do_rpc(node, func, num_args - 2, argv, argvs, &size);
	if (response) {
		// here we do not free varargs for performance reasons
		char *ret = estrndup(response, size);
		free(response);
#ifdef UWSGI_PHP7
		RETURN_STRING(ret);
#else
		RETURN_STRING(ret, 0);
#endif
	}

clear:
	efree(varargs);
	RETURN_NULL();

}

ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_cache_get, 0)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, cache)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_cache_get) {

	char *key = NULL;
	size_t keylen = 0;
	char *cache = NULL;
	size_t cachelen = 0;
	uint64_t valsize;

	if (!uwsgi.caches)
		RETURN_NULL();

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STRING(key, keylen)
	Z_PARAM_OPTIONAL Z_PARAM_STRING(cache, cachelen)
	 ZEND_PARSE_PARAMETERS_END();

	char *value = uwsgi_cache_magic_get(key, keylen, &valsize, NULL, cache);
	if (value)
#ifdef UWSGI_PHP7
		RETURN_STRINGL(value, valsize);
#else
		RETURN_STRINGL(value, valsize, 0);
#endif

	RETURN_NULL();
}

ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_cache_set, 0)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, value)
ZEND_ARG_INFO(0, expires)
ZEND_ARG_INFO(0, cache)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_cache_set) {
	char *key = NULL;
	size_t keylen;
	char *value = NULL;
	size_t vallen;
	char *cache = NULL;
	size_t cachelen = 0;

	zend_long expires = 0;
	if (!uwsgi.caches)
		RETURN_NULL();

	ZEND_PARSE_PARAMETERS_START(2, 4)
		Z_PARAM_STRING(key, keylen)
		Z_PARAM_STRING(value, vallen)
	Z_PARAM_OPTIONAL Z_PARAM_LONG(expires)
	 Z_PARAM_STRING(cache, cachelen)
	 ZEND_PARSE_PARAMETERS_END();

	if (!uwsgi_cache_magic_set(key, keylen, value, vallen, expires, UWSGI_CACHE_FLAG_UPDATE, cache)) {
		RETURN_TRUE;
	}
	RETURN_NULL();

}


ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_cache_update, 0)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, value)
ZEND_ARG_INFO(0, expires)
ZEND_ARG_INFO(0, cache)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_cache_update) {
	char *key = NULL;
	size_t keylen;
	char *value = NULL;
	size_t vallen;
	char *cache = NULL;
	size_t cachelen = 0;

	zend_long expires = 0;
	if (!uwsgi.caches)
		RETURN_NULL();

	ZEND_PARSE_PARAMETERS_START(2, 4)
		Z_PARAM_STRING(key, keylen)
		Z_PARAM_STRING(value, vallen)
	Z_PARAM_OPTIONAL Z_PARAM_LONG(expires)
	 Z_PARAM_STRING(cache, cachelen)
	 ZEND_PARSE_PARAMETERS_END();

	if (!uwsgi_cache_magic_set(key, keylen, value, vallen, expires, UWSGI_CACHE_FLAG_UPDATE, cache)) {
		RETURN_TRUE;
	}
	RETURN_NULL();

}

ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_cache_del, 0)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, cache)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_cache_del) {

	char *key = NULL;
	size_t keylen = 0;
	char *cache = NULL;
	size_t cachelen = 0;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STRING(key, keylen)
	Z_PARAM_OPTIONAL Z_PARAM_STRING(cache, cachelen)
	 ZEND_PARSE_PARAMETERS_END();

	if (!uwsgi_cache_magic_del(key, keylen, cache)) {
		RETURN_TRUE;
	}

	RETURN_NULL();
}

ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_cache_clear, 0)
ZEND_ARG_INFO(0, cache)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_cache_clear) {

	char *cache = NULL;
	size_t cachelen = 0;

	ZEND_PARSE_PARAMETERS_START(0, 1)
	Z_PARAM_OPTIONAL Z_PARAM_STRING(cache, cachelen)
	 ZEND_PARSE_PARAMETERS_END();

	if (!uwsgi_cache_magic_clear(cache)) {
		RETURN_TRUE;
	}

	RETURN_NULL();
}

ZEND_BEGIN_ARG_INFO(arginfo_uwsgi_cache_exists, 0)
ZEND_ARG_INFO(0, key)
ZEND_ARG_INFO(0, cache)
ZEND_END_ARG_INFO()
PHP_FUNCTION(uwsgi_cache_exists) {

	char *key = NULL;
	size_t keylen = 0;
	char *cache = NULL;
	size_t cachelen = 0;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_STRING(key, keylen)
	Z_PARAM_OPTIONAL Z_PARAM_STRING(cache, cachelen)
	 ZEND_PARSE_PARAMETERS_END();

	if (uwsgi_cache_magic_exists(key, keylen, cache)) {
		RETURN_TRUE;
	}

	RETURN_NULL();
}

zend_function_entry uwsgi_php_functions[] = {
	PHP_FE(uwsgi_version, arginfo_uwsgi_version)
	PHP_FE(uwsgi_setprocname, arginfo_uwsgi_setprocname)
	PHP_FE(uwsgi_worker_id, arginfo_uwsgi_worker_id)
	PHP_FE(uwsgi_masterpid, arginfo_uwsgi_masterpid)
	PHP_FE(uwsgi_signal, arginfo_uwsgi_signal)
	PHP_FE(uwsgi_rpc, arginfo_uwsgi_rpc)

	PHP_FE(uwsgi_cache_get, arginfo_uwsgi_cache_get)
	PHP_FE(uwsgi_cache_set, arginfo_uwsgi_cache_set)
	PHP_FE(uwsgi_cache_update, arginfo_uwsgi_cache_update)
	PHP_FE(uwsgi_cache_del, arginfo_uwsgi_cache_del)
	PHP_FE(uwsgi_cache_clear, arginfo_uwsgi_cache_clear)
	PHP_FE(uwsgi_cache_exists, arginfo_uwsgi_cache_exists)
	{NULL, NULL, NULL},
};
extern ps_module ps_mod_uwsgi;
PHP_MINIT_FUNCTION(uwsgi_php_minit) {
	php_session_register_module(&ps_mod_uwsgi);
	return SUCCESS;
}


PHP_MINFO_FUNCTION(uwsgi_php_minfo) {
	php_info_print_table_start();
	php_info_print_table_row(2, "api", "enabled");
	if (uwsgi.caches) {
		php_info_print_table_row(2, "cache", "enabled");
	}
	else {
		php_info_print_table_row(2, "cache", "disabled");
	}
	php_info_print_table_end();
}

zend_module_entry php_cache_module_entry = {
	STANDARD_MODULE_HEADER,
	"Veredis Quo",
	uwsgi_php_functions,
	PHP_MINIT(uwsgi_php_minit),
	NULL,
	NULL,
	NULL,
	PHP_MINFO(uwsgi_php_minfo),
	VEREDIS_QUE_VERSION,
	STANDARD_MODULE_PROPERTIES
};
