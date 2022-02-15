
What is this?
-------------

These functional tests are run with the [bats-core](https://github.com/bats-core/bats-core) framework, which is an
active fork of the older BATS (Bash Automated Testing System).


How to use it
-------------

Run `make bats-all` to perform a test build + run.

To repeat test runs without rebuilding crowdsec, use `make bats-test`.


How does it work?
-----------------

In BATS, you write tests in the form of Bash functions that have names. You can do almost anything that you can normally do in a
shell function. If there is any error condition, the test fails. A set of functions is provided to implement assertions, and
a mechanism of setup/teardown is provided a the level of individual tests (functions) or group of tests (files).

The stdout/stderr of the commands within the tests are captured by bats-core and will only be shown if the test fails.
If you want, to debug your cases, print something ALWAYS, just redirect it to the reserved file descriptor 3:

```
@test "mytest" {
   run some-command
   assert_success
   echo "hello world" >&3
}
```

If you do that, please remove it once the test is finished, because this practice breaks the test protocol.

You can find here the documentation for the main framework and the plugins we use in this test suite:

 - [bats-core tutorial](https://bats-core.readthedocs.io/en/stable/tutorial.html)
 - [bats-assert](https://github.com/bats-core/bats-assert)
 - [bats-support](https://github.com/bats-core/bats-support)
 - [bats-file](https://github.com/bats-core/bats-file)

> As it often happens with open source, the first results from search engines refer to the old, unmaintained forks.
> Be sure to use the links above to find the good versions.


Since bats-core is [TAP (Test Anything Protocol)](https://testanything.org/)
compliant, its output is in a standardized format. It can be integrated with a separate [tap reporter](https://www.npmjs.com/package/tape#pretty-reporters) or included in a
larger test suite. The TAP specification is pretty minimalist and some glue may be needed.


Other tools that you can find useful:

 - [mikefarah/yq](https://github.com/mikefarah/yq) - to parse and update YAML files on the fly
 - [aliou/bats.vim](https://github.com/aliou/bats.vim) - for syntax highlighting (use bash otherwise)

Testing crowdsec
----------------

XXX TODO

How to contribute
-----------------

XXX TODO

