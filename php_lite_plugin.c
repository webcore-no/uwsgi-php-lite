#include "common.h"
#include "php_cache_module.h"

static sapi_module_struct uwsgi_sapi_module;

static int uwsgi_php_init(void);

struct uwsgi_php {
	struct uwsgi_string_list *opcache_files;
	struct uwsgi_string_list *allowed_scripts;
	struct uwsgi_string_list *index;
	struct uwsgi_string_list *set;
	struct uwsgi_string_list *append_config;
	char *docroot;
	char *app;
	char *app_qs;
	char *app_bypass;
	size_t ini_size;
	int dump_config;
	char *server_software;
	size_t server_software_len;
	char *sapi_name;
	int sapi_initialized;
} uphp;

void uwsgi_opt_php_ini(char *opt, char *value, void *foobar) {
	uwsgi_sapi_module.php_ini_path_override = uwsgi_str(value);
	uwsgi_sapi_module.php_ini_ignore = 1;
}

void uwsgi_opt_early_php(char *opt, char *value, void *foobar) {
	uwsgi_php_init();
}

void uwsgi_preload_file(char *name,char *search, char *replace) {
		if(strcmp(name+strlen(name)-4,".php") == 0) {
		int fd = open(name,0);
		if (fd) {
				char *split = name + strlen(search);
				char *new_name = uwsgi_concat2(replace,split);
				zend_file_handle fh;
				fh.type = ZEND_HANDLE_FD;
				fh.opened_path = NULL;
				fh.free_filename = 0;
				fh.filename = new_name;
				fh.handle.fd = fd;
				uwsgi_log("Adding %s to opcache as %s\n",name,new_name);

				if(php_request_startup(TSRMLS_C) == FAILURE) {
					uwsgi_error("php_request_startup()");
					return;
				}
				SG(headers_sent) = 1;
				SG(request_info).no_headers = 1;
				php_lint_script(&fh);
				php_request_shutdown(NULL);
				close(fd);
				free(new_name);
			}
			else {
				uwsgi_error("open()");
			}
		}
}

static void sapi_uwsgi_register_variables(zval* );
void uwsgi_opt_php_add_opcache_preload(char *opt, char *value, void*foo) {
	if(value) {
		sapi_module.register_server_variables = NULL;
		size_t size;
		char *opt_remove = strchr(value,' ');
		char *opt_replace = strchr(opt_remove+1,' ');
		opt_remove[0] = 0;
		opt_replace[0] = 0;
		char *files = uwsgi_open_and_read(value,&size,1,NULL);
		char *prev = files;
		char *next = strchr(files,'\n');
		while (prev != 0) {
			next[0] = 0;
			uwsgi_preload_file(prev,opt_remove+1,opt_replace+1);
			next[0] = '\n';
			prev = next+1;
			next = strchrnul(prev,'\n');
			if(next[0] == 0) {
				break;
			}
		}
		opt_remove[0] = ' ';
		opt_replace[0] = ' ';
		sapi_module.register_server_variables = sapi_uwsgi_register_variables;
	}
}
struct uwsgi_option uwsgi_php_options[] = {
	{"php-ini", required_argument, 0, "set php.ini path", uwsgi_opt_php_ini, NULL, 0},
	{"php-opcache-preload",required_argument,0, "...",uwsgi_opt_php_add_opcache_preload,NULL,0},
	{"php-config", required_argument, 0, "set php.ini path", uwsgi_opt_php_ini, NULL, 0},
	{"php-ini-append", required_argument, 0, "set php.ini path (append mode)", uwsgi_opt_add_string_list, &uphp.append_config, 0},
	{"php-config-append", required_argument, 0, "set php.ini path (append mode)", uwsgi_opt_add_string_list, &uphp.append_config, 0},
	{"php-set", required_argument, 0, "set a php config directive", uwsgi_opt_add_string_list, &uphp.set, 0},
	{"php-index", required_argument, 0, "list the php index files", uwsgi_opt_add_string_list, &uphp.index, 0},
	{"php-docroot", required_argument, 0, "force php DOCUMENT_ROOT", uwsgi_opt_set_str, &uphp.docroot, 0},
	{"php-allowed-script", required_argument, 0, "list the allowed php scripts (require absolute path)", uwsgi_opt_add_string_list, &uphp.allowed_scripts, 0},
	{"php-server-software", required_argument, 0, "force php SERVER_SOFTWARE", uwsgi_opt_set_str, &uphp.server_software, 0},
	{"php-app", required_argument, 0, "force the php file to run at each request", uwsgi_opt_set_str, &uphp.app, 0},
	{"php-app-qs", required_argument, 0, "when in app mode force QUERY_STRING to the specified value + REQUEST_URI", uwsgi_opt_set_str, &uphp.app_qs, 0},
#ifdef UWSGI_PCRE
	{"php-app-bypass", required_argument, 0, "if the regexp matches the uri the --php-app is bypassed", uwsgi_opt_add_regexp_list, &uphp.app_bypass, 0},
#endif
	{"php-dump-config", no_argument, 0, "dump php config (if modified via --php-set or append options)", uwsgi_opt_true, &uphp.dump_config, 0},
	{"php-sapi-name", required_argument, 0, "hack the sapi name (required for enabling zend opcode cache)", uwsgi_opt_set_str, &uphp.sapi_name, 0},
	{"early-php", no_argument, 0, "initialize an early perl interpreter shared by all loaders", uwsgi_opt_early_php, NULL, UWSGI_OPT_IMMEDIATE},
	{"early-php-sapi-name", required_argument, 0, "hack the sapi name (required for enabling zend opcode cache)", uwsgi_opt_set_str, &uphp.sapi_name, UWSGI_OPT_IMMEDIATE},
	UWSGI_END_OF_OPTIONS
};


#ifdef UWSGI_PHP7
static size_t sapi_uwsgi_ub_write(const char *str, size_t str_length TSRMLS_DC)
#else
static int sapi_uwsgi_ub_write(const char *str, uint str_length TSRMLS_DC)
#endif
{
	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);

	uwsgi_response_write_body_do(wsgi_req, (char *) str, str_length);
	if (wsgi_req->write_errors > uwsgi.write_errors_tolerance) {
		php_handle_aborted_connection();
		return -1;
	}
	return str_length;
}

static int sapi_uwsgi_send_headers(sapi_headers_struct * sapi_headers TSRMLS_DC) {
	sapi_header_struct *h;
	zend_llist_position pos;

	if (SG(request_info).no_headers == 1) {
		return SAPI_HEADER_SENT_SUCCESSFULLY;
	}

	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);

	char *accept_key = "UWSGI_ACCEPT_TIMESTAMP";
	char timebuf[256];
	if(snprintf(timebuf,256,"%d",wsgi_req->start_of_request/1000)) {
		uwsgi_response_add_header(wsgi_req,accept_key,strlen(accept_key),timebuf,strlen(timebuf));
	}
	if (!SG(sapi_headers).http_status_line) {
		char status[4];
		int hrc = SG(sapi_headers).http_response_code;
		if (!hrc)
			hrc = 200;
		uwsgi_num2str2n(hrc, status, 4);
		if (uwsgi_response_prepare_headers(wsgi_req, status, 3))
			return SAPI_HEADER_SEND_FAILED;
	}
	else {
		char *sl = SG(sapi_headers).http_status_line;
		if (uwsgi_response_prepare_headers(wsgi_req, sl + 9, strlen(sl + 9)))
			return SAPI_HEADER_SEND_FAILED;
	}

	h = zend_llist_get_first_ex(&sapi_headers->headers, &pos);
	while (h) {
		uwsgi_response_add_header(wsgi_req, NULL, 0, h->header, h->header_len);
		h = zend_llist_get_next_ex(&sapi_headers->headers, &pos);
	}

	return SAPI_HEADER_SENT_SUCCESSFULLY;
}

#ifdef UWSGI_PHP7
static size_t sapi_uwsgi_read_post(char *buffer, size_t count_bytes TSRMLS_DC)
#else
static int sapi_uwsgi_read_post(char *buffer, uint count_bytes TSRMLS_DC)
#endif
{
	uint read_bytes = 0;

	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);

	count_bytes = MIN(count_bytes, wsgi_req->post_cl - SG(read_post_bytes));

	while (read_bytes < count_bytes) {
		ssize_t rlen = 0;
		char *buf = uwsgi_request_body_read(wsgi_req, count_bytes - read_bytes, &rlen);
		if (buf == uwsgi.empty)
			break;
		if (buf) {
			memcpy(buffer, buf, rlen);
			read_bytes += rlen;
			continue;
		}
		break;
	}

	return read_bytes;
}


static char *sapi_uwsgi_read_cookies(TSRMLS_D) {
	uint16_t len = 0;
	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);

	char *cookie = uwsgi_get_var(wsgi_req, (char *) "HTTP_COOKIE", 11, &len);
	if (cookie) {
		return estrndup(cookie, len);
	}

	return NULL;
}

static void sapi_uwsgi_register_variables(zval * track_vars_array TSRMLS_DC) {
	int i;
	struct wsgi_request *wsgi_req = (struct wsgi_request *) SG(server_context);
	php_import_environment_variables(track_vars_array TSRMLS_CC);

	if (uphp.server_software) {
		if (!uphp.server_software_len)
			uphp.server_software_len = strlen(uphp.server_software);
		php_register_variable_safe("SERVER_SOFTWARE", uphp.server_software, uphp.server_software_len, track_vars_array TSRMLS_CC);
	}
	else {
		php_register_variable_safe("SERVER_SOFTWARE", "uWSGI", 5, track_vars_array TSRMLS_CC);
	}

	for (i = 0; i < wsgi_req->var_cnt; i += 2) {
		php_register_variable_safe(estrndup(wsgi_req->hvec[i].iov_base, wsgi_req->hvec[i].iov_len), wsgi_req->hvec[i + 1].iov_base, wsgi_req->hvec[i + 1].iov_len, track_vars_array TSRMLS_CC);
	}

	php_register_variable_safe("PATH_INFO", wsgi_req->path_info, wsgi_req->path_info_len, track_vars_array TSRMLS_CC);
	if (wsgi_req->query_string_len > 0) {
		php_register_variable_safe("QUERY_STRING", wsgi_req->query_string, wsgi_req->query_string_len, track_vars_array TSRMLS_CC);
	}

	php_register_variable_safe("SCRIPT_NAME", wsgi_req->script_name, wsgi_req->script_name_len, track_vars_array TSRMLS_CC);
	php_register_variable_safe("SCRIPT_FILENAME", wsgi_req->file, wsgi_req->file_len, track_vars_array TSRMLS_CC);

	php_register_variable_safe("DOCUMENT_ROOT", wsgi_req->document_root, wsgi_req->document_root_len, track_vars_array TSRMLS_CC);

	if (wsgi_req->path_info_len) {
		char *path_translated = ecalloc(1, wsgi_req->file_len + wsgi_req->path_info_len + 1);

		memcpy(path_translated, wsgi_req->file, wsgi_req->file_len);
		memcpy(path_translated + wsgi_req->file_len, wsgi_req->path_info, wsgi_req->path_info_len);
		php_register_variable_safe("PATH_TRANSLATED", path_translated, wsgi_req->file_len + wsgi_req->path_info_len, track_vars_array TSRMLS_CC);
	}
	else {
		php_register_variable_safe("PATH_TRANSLATED", "", 0, track_vars_array TSRMLS_CC);
	}

	php_register_variable_safe("PHP_SELF", wsgi_req->script_name, wsgi_req->script_name_len, track_vars_array TSRMLS_CC);
}

static sapi_module_struct uwsgi_sapi_module;

static void uwsgi_php_disable(char *value, int (*zend_disable) (char *, size_t)) {	/* {{{ */
	char *s = 0, *e = value;

	while (*e) {
		switch (*e) {
		case ' ':
		case ',':
			if (s) {
				*e = '\0';
				zend_disable(s, e - s);
				s = 0;
			}
			break;
		default:
			if (!s) {
				s = e;
			}
			break;
		}
		e++;
	}

	if (s) {
		zend_disable(s, e - s);
	}
}

static int uwsgi_php_zend_alter_master_ini(char *key, char *val, int mode, int stage) {
	zend_ini_entry *ini_entry;
	zend_string *duplicate;

	if ((ini_entry = zend_hash_str_find_ptr(EG(ini_directives), key, strlen(key))) == NULL)
		return FAILURE;

	duplicate = zend_string_init(val, strlen(val), 1);

	if (!ini_entry->on_modify || ini_entry->on_modify(ini_entry, duplicate, ini_entry->mh_arg1, ini_entry->mh_arg2, ini_entry->mh_arg3, stage) == SUCCESS) {
		ini_entry->value = duplicate;

		if (mode == ZEND_INI_SYSTEM)
			ini_entry->modifiable = mode;
	}
	else
		zend_string_release(duplicate);

	return SUCCESS;
}

int uwsgi_php_apply_defines_ex(char *key, char *val, int *mode) {
	if (uwsgi_php_zend_alter_master_ini(key, val, ZEND_INI_SYSTEM, PHP_INI_STAGE_ACTIVATE) == FAILURE)
		return -1;

	if (!strcmp(key, "disable_functions") && *val) {
		char *v = strdup(val);
		PG(disable_functions) = v;
		uwsgi_php_disable(v, zend_disable_function);
	}
	else if (!strcmp(key, "disable_classes") && *val) {
		char *v = strdup(val);
		PG(disable_classes) = v;
		uwsgi_php_disable(v, zend_disable_class);
	}

	return 1;
}

void uwsgi_php_zend_ini_parser_cb(zval * arg1, zval * arg2, zval * arg3, int callback_type, void *arg) {
	switch (callback_type) {
	case ZEND_INI_PARSER_ENTRY:
		{
			char *argone = strdup(Z_STRVAL_P(arg1));
			char *argtwo = strdup(Z_STRVAL_P(arg2));
			uwsgi_php_apply_defines_ex(argone, argtwo, (int *) arg);
			free(argone);
			free(argtwo);
		}
		break;
	default:
		uwsgi_log("unsupported INI syntax\n");
		break;
	}
}

void uwsgi_php_admin_value(char *opt) {
	zend_parse_ini_string(opt, 1, ZEND_INI_SCANNER_NORMAL, (zend_ini_parser_cb_t) uwsgi_php_zend_ini_parser_cb, (void *) ZEND_INI_SYSTEM);
}

void uwsgi_php_append_config(char *filename) {
	size_t file_size = 0;
	char *file_content = uwsgi_open_and_read(filename, &file_size, 1, NULL);
	uwsgi_sapi_module.ini_entries = realloc(uwsgi_sapi_module.ini_entries, uphp.ini_size + file_size);
	memcpy(uwsgi_sapi_module.ini_entries + uphp.ini_size, file_content, file_size);
	uphp.ini_size += file_size - 1;
	free(file_content);
}

void uwsgi_php_set(char *opt) {

	uwsgi_sapi_module.ini_entries = realloc(uwsgi_sapi_module.ini_entries, uphp.ini_size + strlen(opt) + 2);
	memcpy(uwsgi_sapi_module.ini_entries + uphp.ini_size, opt, strlen(opt));

	uphp.ini_size += strlen(opt) + 1;
	uwsgi_sapi_module.ini_entries[uphp.ini_size - 1] = '\n';
	uwsgi_sapi_module.ini_entries[uphp.ini_size] = 0;
}

static int php_uwsgi_startup(sapi_module_struct * sapi_module) {

	if (php_module_startup(&uwsgi_sapi_module, &php_cache_module_entry, 1) == FAILURE) {
		return FAILURE;
	}
	else {
		return SUCCESS;
	}
}
#if ((PHP_MAJOR_VERSION >= 7) && (PHP_MINOR_VERSION >= 1))
static void sapi_uwsgi_log_message(char *message, int syslog_type_int) {
#else
static void sapi_uwsgi_log_message(char *message TSRMLS_DC) {
#endif
	_uwsgi_report("PHP",zend_get_executed_filename(),zend_get_executed_lineno(),INFO,"%s\n",message);
}
int sapi_uwsgi_activate() {

	return SUCCESS;
}

static sapi_module_struct uwsgi_sapi_module = {
	"uwsgi",
	"uWSGI/php",

	php_uwsgi_startup,
	php_module_shutdown_wrapper,

	sapi_uwsgi_activate,			/* activate */
	NULL,			/* deactivate */

	sapi_uwsgi_ub_write,
	NULL,
	NULL,			/* get uid */
	NULL,			/* getenv */

	php_error,

	NULL,
	sapi_uwsgi_send_headers,
	NULL,
	sapi_uwsgi_read_post,
	sapi_uwsgi_read_cookies,

	sapi_uwsgi_register_variables,
	sapi_uwsgi_log_message,	/* Log message */
	NULL,			/* Get request time */
	NULL,			/* Child terminate */

	STANDARD_SAPI_MODULE_PROPERTIES
};


static int uwsgi_php_init(void) {
	struct uwsgi_string_list *pset = uphp.set;
	struct uwsgi_string_list *append_config = uphp.append_config;

	if (!uphp.sapi_initialized) {
#ifdef ZTS
		tsrm_startup(1, 1, 0, NULL);
#endif
		sapi_startup(&uwsgi_sapi_module);
		uphp.sapi_initialized = 1;
	}

	// applying custom options
	while (append_config) {
		uwsgi_php_append_config(append_config->value);
		append_config = append_config->next;
	}
	while (pset) {
		uwsgi_php_set(pset->value);
		uwsgi_php_admin_value(pset->value);
		pset = pset->next;
	}

	if (uphp.dump_config) {
		uwsgi_log("--- PHP custom config ---\n\n");
		uwsgi_log("%s\n", uwsgi_sapi_module.ini_entries);
		uwsgi_log("--- end of PHP custom config ---\n");
	}

	// fix docroot
	if (uphp.docroot) {
		char *orig_docroot = uphp.docroot;
		uphp.docroot = uwsgi_expand_path(uphp.docroot, strlen(uphp.docroot), NULL);
		if (!uphp.docroot) {
			uwsgi_log("unable to set php docroot to %s\n", orig_docroot);
			exit(1);
		}
	}

	if (uphp.sapi_name) {
		uwsgi_sapi_module.name = uphp.sapi_name;
	}

	uwsgi_sapi_module.startup(&uwsgi_sapi_module);

	uwsgi_log("PHP %s initialized\n", PHP_VERSION);
	return 0;
}

int uwsgi_php_request(struct wsgi_request *wsgi_req) {

	char real_filename[PATH_MAX + 1];
	zend_file_handle file_handle;

#ifdef ZTS
	TSRMLS_FETCH();
#endif
	SG(server_context) = (void *) wsgi_req;

	if (uwsgi_parse_vars(wsgi_req)) {
		return -1;
	}


	if (uphp.docroot) {
		wsgi_req->document_root = uphp.docroot;
	}
	// fallback to cwd
	else if (!wsgi_req->document_root_len) {
		wsgi_req->document_root = uwsgi.cwd;
	}
	else {
		// explode DOCUMENT_ROOT (both for security and sanity checks)
		// this memory will be cleared on request end
		char *sanitized_docroot = ecalloc(1, PATH_MAX + 1);
		if (!uwsgi_expand_path(wsgi_req->document_root, wsgi_req->document_root_len, sanitized_docroot)) {
			efree(sanitized_docroot);
			return -1;
		}
		wsgi_req->document_root = sanitized_docroot;
	}

	// fix document_root_len
	wsgi_req->document_root_len = strlen(wsgi_req->document_root);

	if (uphp.app) {
		strncpy(real_filename, uphp.app, PATH_MAX);
		real_filename[PATH_MAX - 1] = '\0';
		if (wsgi_req->path_info_len == 1 && wsgi_req->path_info[0] == '/') {
			goto appready;
		}
		if (uphp.app_qs) {
			size_t app_qs_len = strlen(uphp.app_qs);
			size_t qs_len = wsgi_req->path_info_len + app_qs_len;
			if (wsgi_req->query_string_len > 0) {
				qs_len += 1 + wsgi_req->query_string_len;
			}
			char *qs = ecalloc(1, qs_len + 1);
			memcpy(qs, uphp.app_qs, app_qs_len);
			memcpy(qs + app_qs_len, wsgi_req->path_info, wsgi_req->path_info_len);
			if (wsgi_req->query_string_len > 0) {
				char *ptr = qs + app_qs_len + wsgi_req->path_info_len;
				*ptr = '&';
				memcpy(ptr + 1, wsgi_req->query_string, wsgi_req->query_string_len);
			}
			wsgi_req->query_string = qs;
			wsgi_req->query_string_len = qs_len;
		}
appready:
		wsgi_req->path_info = "";
		wsgi_req->path_info_len = 0;
		wsgi_req->script_name = "";
		wsgi_req->script_name_len = 0;
	}

	wsgi_req->file = real_filename;
	wsgi_req->file_len = strlen(wsgi_req->file);

	if (uphp.allowed_scripts) {
		struct uwsgi_string_list *usl = uphp.allowed_scripts;
		while (usl) {
			if (!uwsgi_strncmp(wsgi_req->file, wsgi_req->file_len, usl->value, usl->len)) {
				goto secure3;
			}
			usl = usl->next;
		}
		uwsgi_403(wsgi_req);
		uwsgi_log("PHP security error: %s is not an allowed script\n", real_filename);
		return -1;
	}

secure3:

#ifdef UWSGI_DEBUG
	uwsgi_log("php filename = %s script_name = %.*s (%d) document_root = %.*s (%d)\n", real_filename, wsgi_req->script_name_len, wsgi_req->script_name, wsgi_req->script_name_len, wsgi_req->document_root_len, wsgi_req->document_root, wsgi_req->document_root_len);
#endif

	// now check for allowed paths and extensions

	SG(request_info).request_uri = estrndup(wsgi_req->uri, wsgi_req->uri_len);
	SG(request_info).request_method = estrndup(wsgi_req->method, wsgi_req->method_len);
	SG(request_info).proto_num = 1001;

	SG(request_info).query_string = estrndup(wsgi_req->query_string, wsgi_req->query_string_len);
	SG(request_info).content_length = wsgi_req->post_cl;
	SG(request_info).content_type = estrndup(wsgi_req->content_type, wsgi_req->content_type_len);

	// reinitialize it at every request !!!
	SG(sapi_headers).http_response_code = 200;

	SG(request_info).path_translated = wsgi_req->file;

	file_handle.type = ZEND_HANDLE_FILENAME;
	file_handle.filename = real_filename;
	file_handle.free_filename = 0;
	file_handle.opened_path = NULL;

	if (php_request_startup(TSRMLS_C) == FAILURE) {
		uwsgi_500(wsgi_req);
		return -1;
	}
	// TODO: move to:
	// zend_execute_scripts(ZEND_REQUIRE, NULL, 3, prepend_file_p, primary_file, append_file_p) == SUCCESS
	php_execute_script(&file_handle TSRMLS_CC);
	php_request_shutdown(NULL);

	return 0;
}

void uwsgi_php_after_request(struct wsgi_request *wsgi_req) {

	log_request(wsgi_req);
}

SAPI_API struct uwsgi_plugin php_lite_plugin = {
	.name = "php_lite",
	.modifier1 = 14,
	.init = uwsgi_php_init,
	.request = uwsgi_php_request,
	.after_request = uwsgi_php_after_request,
	.options = uwsgi_php_options,
};
