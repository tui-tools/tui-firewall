package main

import "errors"

// errFake is the failure injected into the fake backend by the tests.
var errFake = errors.New("ufw: permission denied")
