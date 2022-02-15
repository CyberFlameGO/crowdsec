#!/usr/bin/env bats
# vim: ft=bats:list:ts=8:sts=4:sw=4:et:ai:si:

set -u

LIB="$(dirname "$BATS_TEST_FILENAME")/lib"
load "${LIB}/bats-support/load.bash"
load "${LIB}/bats-assert/load.bash"

#declare stderr
CSCLI="${BIN_DIR}/cscli"

setup_file() {
    echo "# --- $(basename "${BATS_TEST_FILENAME}" .bats)" >&3
    #shellcheck source=tests/bats/lib/assert-crowdsec-not-running.sh
    . "${LIB}/assert-crowdsec-not-running.sh"
}

teardown_file() {
    :
}

setup() {
    "${TEST_DIR}/instance-data" load
    "${TEST_DIR}/instance-crowdsec" start
}

teardown() {
    "${TEST_DIR}/instance-crowdsec" stop
}

#----------

@test "hub tests" {
    skip
    repodir=$(mktemp -d)
    run git clone --depth 1 https://github.com/crowdsecurity/hub.git "${repodir}"
    assert_success
    pushd "${repodir}"
    run "${CSCLI}" hubtest run --all --clean
    # needed to see what's broken
    echo "$output"
    assert_success
    popd
    rm -rf -- "${repodir}"
}

