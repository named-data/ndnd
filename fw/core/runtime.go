/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package core

import "time"

// Version of YaNFD.
var Version string

// StartTimestamp is the time the forwarder was started.
var StartTimestamp time.Time

// ShouldQuit indicates whether threads should quit
var ShouldQuit = false
