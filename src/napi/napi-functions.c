#include <node_api.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#define check_type(env, value, expectedType) do { \
	napi_valuetype __t; \
	napi_status __s = napi_typeof(env, value, &__t); \
	if (__s != napi_ok) goto fail; \
	if (__t != expectedType) goto fail; \
} while (0)
static napi_value make_socket(napi_env env, napi_callback_info info) {
	napi_status s;
	napi_value arguments[4];
	size_t argc = 4;
	int socket_fd = -1;
	s = napi_get_cb_info(env, info, &argc, arguments, NULL, NULL);
	if (s != napi_ok) goto fail;
	check_type(env, arguments[0], napi_number);
	check_type(env, arguments[1], napi_number);
	check_type(env, arguments[2], napi_number);
	int32_t domain, type, protocol;
	if (napi_get_value_int32(env, arguments[0], &domain) != napi_ok) goto fail;
	if (napi_get_value_int32(env, arguments[1], &type) != napi_ok) goto fail;
	if (napi_get_value_int32(env, arguments[2], &protocol) != napi_ok) goto fail;
	socket_fd = socket(domain, type | SOCK_NONBLOCK | SOCK_CLOEXEC, protocol);
	if (socket_fd < 0) goto report_error;
	napi_valuetype t;
	if (napi_typeof(env, arguments[3], &t) != napi_ok) goto fail;
	if (t == napi_object) {
		uint32_t length;
		if (napi_get_array_length(env, arguments[3], &length) != napi_ok) goto fail;
		for (uint32_t i = 0; i < length; i++) {
			napi_value v;
			if (napi_get_element(env, arguments[3], i, &v) != napi_ok) goto fail;
			napi_value vt;
			if (napi_get_named_property(env, v, "type", &vt) != napi_ok) goto fail;
			check_type(env, vt, napi_number);
			uint32_t vt32;
			uint32_t level = 0;
			uint32_t sockopt = 0;
			void *buf = NULL;
			size_t buf_len = 0;
			if (napi_get_value_uint32(env, vt, &vt32) != napi_ok) goto fail;
			if (napi_get_named_property(env, v, "data", &vt) != napi_ok) goto fail;
			if (napi_get_buffer_info(env, vt, &buf, &buf_len) != napi_ok) goto fail;
			if (vt32 == 3) {
				if (napi_get_named_property(env, v, "level", &vt) != napi_ok) goto fail;
				if (napi_get_value_uint32(env, vt, &level) != napi_ok) goto fail;
				if (napi_get_named_property(env, v, "opt", &vt) != napi_ok) goto fail;
				if (napi_get_value_uint32(env, vt, &sockopt) != napi_ok) goto fail;
				int sso = setsockopt(socket_fd, level, sockopt, buf, buf_len);
				if (sso != 0) goto report_error;
			} else if (vt32 == 2) {
				if (bind(socket_fd, (struct sockaddr *) buf, buf_len) != 0) goto report_error;
			}
		}
	}
	goto success;
report_error:
	;int saved_errno = errno;
	if (socket_fd >= 0) close(socket_fd);
	socket_fd = -saved_errno;
success:
	napi_value result_;
	if (napi_create_int32(env, socket_fd, &result_) != napi_ok) abort();
	return result_;
fail:
	if (socket_fd >= 0) close(socket_fd);
	napi_value result;
	if (napi_get_null(env, &result) != napi_ok) abort();
	return result;
}
napi_value Init(napi_env env, napi_value exports) {
	napi_property_descriptor my_func = {"make_socket", NULL, make_socket, NULL, NULL, NULL, 0, NULL};
	if (napi_define_properties(env, exports, 1, &my_func) != napi_ok) abort();
	return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
