#include "php_cache_module.h"

PHP_FUNCTION(uwsgi_version) {
#ifdef UWSGI_PHP7
	RETURN_STRING(VEREDIS_QUE_VERSION);
#else
	RETURN_STRING(VEREDIS_QUE_VERSION, 1);
#endif
}

PHP_FUNCTION(uwsgi_setprocname) {

	char *name;
	int name_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS()TSRMLS_CC, "s", &name, &name_len) == FAILURE) {
		RETURN_NULL();
	}

	uwsgi_set_processname(estrndup(name, name_len));

	RETURN_NULL();
}

PHP_FUNCTION(uwsgi_worker_id) {
	RETURN_LONG(uwsgi.mywid);
}

PHP_FUNCTION(uwsgi_masterpid) {
	if (uwsgi.master_process) {
		RETURN_LONG(uwsgi.workers[0].pid);
	}
	RETURN_LONG(0);
}

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
	UWSGI_FE(uwsgi_version)
	UWSGI_FE(uwsgi_setprocname)
	UWSGI_FE(uwsgi_worker_id)
	UWSGI_FE(uwsgi_masterpid)
	UWSGI_FE(uwsgi_signal)
	UWSGI_FE(uwsgi_rpc)

	UWSGI_FE(uwsgi_cache_get)
	UWSGI_FE(uwsgi_cache_set)
	UWSGI_FE(uwsgi_cache_update)
	UWSGI_FE(uwsgi_cache_del)
	UWSGI_FE(uwsgi_cache_clear)
	UWSGI_FE(uwsgi_cache_exists) {NULL, NULL, NULL},
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
