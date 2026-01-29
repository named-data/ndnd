/* YaNFD - Yet another NDN Forwarding Daemon
 *
 * Copyright (C) 2020-2021 Eric Newberry.
 *
 * This file is licensed under the terms of the MIT License, as found in LICENSE.md.
 */

package main

import (
	"github.com/named-data/ndnd/fw/cmd"
)

// (AI GENERATED DESCRIPTION): Starts the YaNFD application by executing its root command (CmdYaNFD).
func main() {
	cmd.CmdYaNFD.Execute()
}
