package tools

import (
	"fmt"
	"os"
	"time"

	enc "github.com/named-data/ndnd/std/encoding"
	"github.com/named-data/ndnd/std/engine"
	"github.com/named-data/ndnd/std/log"
	"github.com/named-data/ndnd/std/object"
)

type CatChunks struct {
	args []string
}

func RunCatChunks(args []string) {
	(&CatChunks{args: args}).run()
}

func (cc *CatChunks) String() string {
	return "cat"
}

func (cc *CatChunks) usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <name>\n", cc.args[0])
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Retrieves an object with the specified name.\n")
	fmt.Fprintf(os.Stderr, "The object contents are written to stdout on success.\n")
}

func (cc *CatChunks) run() {
	if len(cc.args) < 2 {
		cc.usage()
		os.Exit(3)
	}

	// get name from cli
	name, err := enc.NameFromStr(cc.args[1])
	if err != nil {
		log.Fatal(cc, "Invalid name", "name", cc.args[1])
	}

	// start face and engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err = app.Start()
	if err != nil {
		log.Error(cc, "Unable to start engine", "err", err)
		return
	}
	defer app.Stop()

	// start object client
	cli := object.NewClient(app, object.NewMemoryStore())
	err = cli.Start()
	if err != nil {
		log.Error(cc, "Unable to start object client", "err", err)
		return
	}
	defer cli.Stop()

	done := make(chan *object.ConsumeState)
	t1, t2 := time.Now(), time.Now()
	byteCount := 0

	// calling Content() on a status object clears the buffer
	// and returns the new data the next time it is called
	write := func(status *object.ConsumeState) {
		content := status.Content()
		os.Stdout.Write(content)
		byteCount += len(content)
	}

	// fetch object
	cli.Consume(name, func(status *object.ConsumeState) bool {
		if status.IsComplete() {
			t2 = time.Now()
			write(status)
			done <- status
		}

		if status.Progress()%1000 == 0 {
			log.Debug(cc, "Consume progress", "progress", float64(status.Progress())/float64(status.ProgressMax())*100)
			write(status)
		}

		return true
	})
	state := <-done

	if state.Error() != nil {
		log.Error(cc, "Error fetching object", "err", state.Error())
		return
	}

	// statistics
	fmt.Fprintf(os.Stderr, "Object fetched %s\n", state.Name())
	fmt.Fprintf(os.Stderr, "Content: %d bytes\n", byteCount)
	fmt.Fprintf(os.Stderr, "Time taken: %s\n", t2.Sub(t1))
	fmt.Fprintf(os.Stderr, "Throughput: %f Mbit/s\n", float64(byteCount*8)/t2.Sub(t1).Seconds()/1e6)

}
