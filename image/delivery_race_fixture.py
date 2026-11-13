"""Explicit test-image instrumentation; never enabled in normal image builds."""


def instrument(dispatcher, quiesce):
    before = "        barrier = daemon_control('quiesce', payload['daemon_identity'])"
    after = "        write_json(STATE / 'race-expected.json', {'id': request_id})\n" + before
    assert dispatcher.count(before) == 1
    dispatcher = dispatcher.replace(before, after)
    before = "        with response.open('rb') as stream:"
    after = """        expected_file = STATE / 'race-expected.json'
        if expected_file.exists() and json.loads(expected_file.read_text())['id'] == path.stem:
            write_json(STATE / 'race-reader.json', {'id': path.stem, 'pid': os.getpid()})
            time.sleep(3)  # Hold the real root deliver inside the service cgroup.
""" + before
    assert dispatcher.count(before) == 1
    dispatcher = dispatcher.replace(before, after)
    before = "        (GROUP / 'cgroup.freeze').write_text('1')"
    after = """        expected_request = json.loads(Path('/run/tempest-control/race-expected.json').read_text())['id']
        reader_file = Path('/run/tempest-control/race-reader.json')
        def reader_ready():
            try:
                reader = json.loads(reader_file.read_text())
                return reader['id'] == expected_request and Path('/proc', str(reader['pid'])).exists()
            except (OSError, ValueError, KeyError):
                return False
        wait_for(reader_ready)
        forced_reader_pid = json.loads(reader_file.read_text())['pid']
""" + before
    assert quiesce.count(before) == 1
    quiesce = quiesce.replace(before, after)
    before = "'frozen_guest_ns': frozen_guest_ns}"
    after = "'frozen_guest_ns': frozen_guest_ns, 'forced_reader_pid': forced_reader_pid}"
    assert quiesce.count(before) == 1
    return dispatcher, quiesce.replace(before, after)
