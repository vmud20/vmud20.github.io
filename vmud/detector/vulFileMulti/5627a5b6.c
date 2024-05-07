


















struct test_packet_id_write_data {
    struct {
        uint32_t buf_id;
        uint32_t buf_time;
    } test_buf_data;
    struct buffer test_buf;
    struct packet_id_send pis;
};

static int test_packet_id_write_setup(void **state) {
    struct test_packet_id_write_data *data = calloc(1, sizeof(struct test_packet_id_write_data));

    if (!data)
    {
        return -1;
    }

    data->test_buf.data = (void *) &data->test_buf_data;
    data->test_buf.capacity = sizeof(data->test_buf_data);

    *state = data;
    return 0;
}

static int test_packet_id_write_teardown(void **state) {
    free(*state);
    return 0;
}

static void test_packet_id_write_short(void **state)
{
    struct test_packet_id_write_data *data = *state;

    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, false, false));
    assert_true(data->pis.id == 1);
    assert_true(data->test_buf_data.buf_id == htonl(1));
    assert_true(data->test_buf_data.buf_time == 0);
}

static void test_packet_id_write_long(void **state)
{
    struct test_packet_id_write_data *data = *state;

    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, true, false));
    assert(data->pis.id == 1);
    assert(data->pis.time == now);
    assert_true(data->test_buf_data.buf_id == htonl(1));
    assert_true(data->test_buf_data.buf_time == htonl(now));
}

static void test_packet_id_write_short_prepend(void **state)
{
    struct test_packet_id_write_data *data = *state;

    data->test_buf.offset = sizeof(packet_id_type);
    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, false, true));
    assert_true(data->pis.id == 1);
    assert_true(data->test_buf_data.buf_id == htonl(1));
    assert_true(data->test_buf_data.buf_time == 0);
}

static void test_packet_id_write_long_prepend(void **state)
{
    struct test_packet_id_write_data *data = *state;

    data->test_buf.offset = sizeof(data->test_buf_data);
    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, true, true));
    assert(data->pis.id == 1);
    assert(data->pis.time == now);
    assert_true(data->test_buf_data.buf_id == htonl(1));
    assert_true(data->test_buf_data.buf_time == htonl(now));
}

static void test_packet_id_write_short_wrap(void **state)
{
    struct test_packet_id_write_data *data = *state;

    data->pis.id = ~0;
    expect_assert_failure( packet_id_write(&data->pis, &data->test_buf, false, false));
}

static void test_packet_id_write_long_wrap(void **state)
{
    struct test_packet_id_write_data *data = *state;

    data->pis.id = ~0;
    now = 5010;
    assert_true(packet_id_write(&data->pis, &data->test_buf, true, false));
    assert(data->pis.id == 1);
    assert(data->pis.time == now);
    assert_true(data->test_buf_data.buf_id == htonl(1));
    assert_true(data->test_buf_data.buf_time == htonl(now));
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(test_packet_id_write_short, test_packet_id_write_setup, test_packet_id_write_teardown), cmocka_unit_test_setup_teardown(test_packet_id_write_long, test_packet_id_write_setup, test_packet_id_write_teardown), cmocka_unit_test_setup_teardown(test_packet_id_write_short_prepend, test_packet_id_write_setup, test_packet_id_write_teardown), cmocka_unit_test_setup_teardown(test_packet_id_write_long_prepend, test_packet_id_write_setup, test_packet_id_write_teardown), cmocka_unit_test_setup_teardown(test_packet_id_write_short_wrap, test_packet_id_write_setup, test_packet_id_write_teardown), cmocka_unit_test_setup_teardown(test_packet_id_write_long_wrap, test_packet_id_write_setup, test_packet_id_write_teardown), };












    return cmocka_run_group_tests_name("packet_id tests", tests, NULL, NULL);
}
