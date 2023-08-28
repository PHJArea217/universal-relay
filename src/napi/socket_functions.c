static napi_value recvmsg_wrapper(napi_env env, napi_callback_info info) {
	struct msghdr msg = {0};
	size_t argc = 5;
	napi_value arguments[5];
	napi_status s = napi_get_cb_info(env, info, &argc, arguments, NULL, NULL);
	if (s != napi_ok) goto fail;
	int fd = -1;
	s = napi_get_value_int32(env, arguments[0], &fd);
	if (s != napi_ok) goto fail;
	uint32_t flags = 0;
	if (napi_get_value_uint32(env, arguments[4], &flags) != napi_ok) goto fail;
	size_t len = 0;
	s = napi_get_array_length(env, arguments[2], &len);
	if (s != napi_ok) goto fail;
	struct iovec *iov = calloc(sizeof(struct iovec), len);
	if (!iov) goto fail;
	for (uint32_t i = 0; i < len; i++) {
		napi_value b;
		if (napi_get_element(env, arguments[2], i, &b) != napi_ok) goto fail;
		if (napi_get_buffer_info(env, b, &iov[i].iov_base, &iov[i].iov_len) != napi_ok) goto fail;
	}
	struct iovec name;
	struct iovec cmsg;
	if (napi_get_buffer_info(env, arguments[1], &name.iov_base, &name.iov_len) != napi_ok) goto fail;
	if (napi_get_buffer_info(env, arguments[3], &cmsg.iov_base, &cmsg.iov_len) != napi_ok) goto fail;
	msg.msg_name = name.iov_base;
	msg.msg_namelen = name.iov_len;
	msg.msg_control = cmsg.iov_base;
	msg.msg_controllen = cmsg.iov_len;
	struct {
		int64_t result;
		uint64_t new_namelen;
		uint64_t new_cmsglen;
		uint64_t new_flags;
		uint64_t sys_errno;
	} buf_out;
	buf_out.result = recvmsg(fd, &msg, flags);
	buf_out.new_namelen = msg.msg_namelen;
	buf_out.new_cmsglen = msg.msg_controllen;
	buf_out.new_flags = msg.msg_flags;
	buf_out.sys_errno = errno;
	free(iov);
	napi_value retval;
	if (napi_create_buffer_copy(env, &buf_out, sizeof(buf_out), NULL, &retval) != napi_ok) goto hard_fail;
	return retval;
}
static napi_value sendmsg_wrapper(napi_env env, napi_callback_info info) {
	struct msghdr msg = {0};
	size_t argc = 5;
	napi_value arguments[5];
	napi_status s = napi_get_cb_info(env, info, &argc, arguments, NULL, NULL);
	if (s != napi_ok) goto fail;
	int fd = -1;
	s = napi_get_value_int32(env, arguments[0], &fd);
	if (s != napi_ok) goto fail;
	uint32_t flags = 0;
	if (napi_get_value_uint32(env, arguments[4], &flags) != napi_ok) goto fail;
	size_t len = 0;
	s = napi_get_array_length(env, arguments[2], &len);
	if (s != napi_ok) goto fail;
	struct iovec *iov = calloc(sizeof(struct iovec), len);
	if (!iov) goto fail;
	for (uint32_t i = 0; i < len; i++) {
		napi_value b;
		if (napi_get_element(env, arguments[2], i, &b) != napi_ok) goto fail;
		if (napi_get_buffer_info(env, b, &iov[i].iov_base, &iov[i].iov_len) != napi_ok) goto fail;
	}
	struct iovec name;
	struct iovec cmsg;
	if (napi_get_buffer_info(env, arguments[1], &name.iov_base, &name.iov_len) != napi_ok) goto fail;
	if (napi_get_buffer_info(env, arguments[3], &cmsg.iov_base, &cmsg.iov_len) != napi_ok) goto fail;
	msg.msg_name = name.iov_base;
	msg.msg_namelen = name.iov_len;
	msg.msg_control = cmsg.iov_base;
	msg.msg_controllen = cmsg.iov_len;
	struct {
		int64_t result;
		uint64_t new_namelen;
		uint64_t new_cmsglen;
		uint64_t new_flags;
		uint64_t sys_errno;
	} buf_out;
	buf_out.result = sendmsg(fd, &msg, flags);
	buf_out.new_namelen = msg.msg_namelen;
	buf_out.new_cmsglen = msg.msg_controllen;
	buf_out.new_flags = msg.msg_flags;
	buf_out.sys_errno = errno;
	free(iov);
	napi_value retval;
	if (napi_create_buffer_copy(env, &buf_out, sizeof(buf_out), NULL, &retval) != napi_ok) goto hard_fail;
	return retval;
}
struct my_uv_poll_data {
	napi_env env;
	uv_poll_t poll;
	napi_async_context async_context;
	napi_value callback_fn;
	napi_value this;
};
void data_finalize(napi_env env, void *data, void *hint) {
	struct my_uv_poll_data *d = data;
	uv_poll_stop(&d->poll);
	napi_async_destroy(env, d->async_context);
}
void data_cb(uv_poll_t *va, int status, int events) {
	struct my_uv_poll_data *v = va->data;
	napi_value s[2];
	if (napi_create_int32(v->env, status, &s[0]) != napi_ok) goto fail;
	if (napi_create_int32(v->env, events, &s[1]) != napi_ok) goto fail;

	napi_value func_retval;
	napi_status st = napi_make_callback(v->env, v->async_context,
			v->this,
			v->callback_fn,
			2,
			&s,
			&func_retval);
	if (st != napi_ok) goto fail;
}
static make_uv_poll_external(napi_env env, napi_callback_info info) {
	napi_value this;
	napi_value argv[3];
	size_t argc = 3;
	struct my_uv_poll_data *data = calloc(sizeof(struct my_uv_poll_data), 1);
	if (!data) goto fail;
	uv_loop_t *loop;
	if (napi_get_uv_event_loop(env, &loop) != napi_ok) goto fail;
	if (napi_get_cb_info(env, info, &argc, argv, &this, NULL) != napi_ok) goto fail;
	int fd = -1;
	if (napi_get_int32(env, argv[0], &fd) != napi_ok) goto fail;
	int retval1 = uv_poll_init(loop, &data->poll, fd);
	if (retval1) goto uv_fail;
	retval1 = uv_poll_start(&data->poll, 0, data_cb);
	if (retval1) goto uv_fail;
	data->poll.data = data;
	data->env = env;
	data->callback_fn = argv[1];
	if (napi_async_init(env, /* ??? */, &data->async_context) != napi_ok) goto fail;
	data->this = this;
	napi_value retval;
	if (napi_create_external(env, data, data_finalize, NULL, &retval) != napi_ok) goto hard_fail;
	return retval;
}
static my_uv_poll_set_events(napi_env env, napi_callback_info info) {
	size_t argc = 2;
	napi_value argv[2];
	int events = 0; struct my_uv_poll_data *data = NULL;
	if (napi_get_cb_info(env, info, &argc, argv, NULL, NULL) != napi_ok) goto fail;
	if (napi_get_value_external(env, argv[0], &data) != napi_ok) goto fail;
	if (napi_get_int32(env, argv[1], &events) != napi_ok) goto fail;
	int retval = uv_poll_start(&data->poll, events, data_cb);
	if (retval) goto uv_fail;
	return argv[0];
}
