package tools

import (
	"fmt"
	"os"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/ndn"
	"github.com/named-data/ndnd/std/object"
	"github.com/named-data/ndnd/std/object/storage"
	"github.com/spf13/cobra"
)

type CatChunks struct{}

// (AI GENERATED DESCRIPTION): Creates a Cobra command that retrieves the data object for a given name prefix and writes its content to standard output.
func CmdCatChunks() *cobra.Command {
	cc := CatChunks{}

	return &cobra.Command{
		GroupID: "tools",
		Use:     "cat PREFIX",
		Short:   "Retrieve object under a name prefix",
		Long: `Retrieve an object with the specified name.
The object contents are written to stdout on success.`,
		Args:    cobra.ExactArgs(1),
		Example: `  ndnd cat /my/example/data > data.bin`,
		Run:     cc.run,
	}
}

// (AI GENERATED DESCRIPTION): Returns the literal string `"cat"` as the textual representation of a `CatChunks` instance.
func (cc *CatChunks) String() string {
	return "cat"
}

// (AI GENERATED DESCRIPTION): Fetches an NDN object by name, streams its payload to standard output, and prints fetch statistics and progress to standard error.
func (cc *CatChunks) run(_ *cobra.Command, args []string) {
	name, err := enc.NameFromStr(args[0])
	if err != nil {
		log.Fatal(cc, "Invalid name", "name", args[0])
		return
	}

	// start face and engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err = app.Start()
	if err != nil {
		log.Fatal(cc, "Unable to start engine", "err", err)
		return
	}
	defer app.Stop()

	// start object client
	cli := object.NewClient(app, storage.NewMemoryStore(), nil)
	err = cli.Start()
	if err != nil {
		log.Fatal(cc, "Unable to start object client", "err", err)
		return
	}
	defer cli.Stop()

	done := make(chan ndn.ConsumeState)
	t1, t2 := time.Now(), time.Now()

	// fetch object
	progress := 0
	cli.ConsumeExt(ndn.ConsumeExtArgs{
		Name: name,
		Callback: func(state ndn.ConsumeState) {
			t2 = time.Now()
			done <- state
		},
		OnProgress: func(state ndn.ConsumeState) {
			if state.Progress()-progress >= 1000 {
				progress = state.Progress()
				log.Debug(cc, "Consume progress", "progress", float64(state.Progress())/float64(state.ProgressMax())*100)
			}
		},
	})
	state := <-done

	if state.Error() != nil {
		log.Fatal(cc, "Error fetching object", "err", state.Error())
		return
	}

	// write object to stdout
	byteCount := 0
	for _, chunk := range state.Content() {
		os.Stdout.Write(chunk)
		byteCount += len(chunk)
	}

	// statistics
	fmt.Fprintf(os.Stderr, "Object fetched %s\n", state.Name())
	fmt.Fprintf(os.Stderr, "Content: %d bytes\n", byteCount)
	fmt.Fprintf(os.Stderr, "Time taken: %s\n", t2.Sub(t1))
	fmt.Fprintf(os.Stderr, "Throughput: %f Mbit/s\n", float64(byteCount*8)/t2.Sub(t1).Seconds()/1e6)
}
