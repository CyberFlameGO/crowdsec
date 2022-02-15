#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

LIB="$(dirname "$BATS_TEST_FILENAME")/lib"
#shellcheck source=tests/bats/lib/assert-crowdsec-not-running.sh
. "${LIB}/assert-crowdsec-not-running.sh"

#declare stderr
CSCLI="${BIN_DIR}/cscli"
CROWDSEC="${BIN_DIR}/crowdsec"

fake_log() {
    for _ in $(seq 1 6) ; do
        echo "$(LC_ALL=C date '+%b %d %H:%M:%S ')"'sd-126005 sshd[12422]: Invalid user netflix from 1.1.1.172 port 35424'
    done;
}

setup_file() {
    echo "# --- $(basename "${BATS_TEST_FILENAME}" .bats)" >&3
    # we reset config and data, but run the daemon only in the tests that need it
    ${TEST_DIR}/instance-data load
}

teardown_file() {
    :
}

setup() {
    load "${LIB}/bats-support/load.bash"
    load "${LIB}/bats-assert/load.bash"
}

teardown() {
    "${TEST_DIR}/instance-crowdsec" stop
}

#----------

@test "live: 1.1.1.172 has been banned" {
    tmpfile=$(mktemp)
    touch "${tmpfile}"
    echo -e "---\nfilename: $tmpfile\nlabels:\n  type: syslog\n" >> "${CONFIG_DIR}/acquis.yaml"
    "${TEST_DIR}/instance-crowdsec" start
    sleep 2s
    fake_log >> "${tmpfile}"
    sleep 2s
    rm -- -f ${tmpfile} || true
    run "${CSCLI}" decisions list -o json
    [[ $(echo "$output" | yq '.[].decisions[0].value') == '1.1.1.172' ]]
    assert_success
}
