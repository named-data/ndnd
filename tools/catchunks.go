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

func (cc *CatChunks) usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <name>\n", cc.args[0])
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "Retrieves an object with the specified name.\n")
	fmt.Fprintf(os.Stderr, "The object contents are written to stdout on success.\n")
}

func (cc *CatChunks) run() {
	log.SetLevel(log.InfoLevel)

	if len(cc.args) < 2 {
		cc.usage()
		os.Exit(3)
	}

	// get name from cli
	name, err := enc.NameFromStr(cc.args[1])
	if err != nil {
		log.Fatalf("Invalid name: %s", cc.args[1])
	}

	// start face and engine
	app := engine.NewBasicEngine(engine.NewDefaultFace())
	err = app.Start()
	if err != nil {
		log.Errorf("Unable to start engine: %+v", err)
		return
	}
	defer app.Stop()

	// start object client
	cli := object.NewClient(app, object.NewMemoryStore())
	err = cli.Start()
	if err != nil {
		log.Errorf("Unable to start object client: %+v", err)
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
			log.Debugf("Progress: %.2f%%", float64(status.Progress())/float64(status.ProgressMax())*100)
			write(status)
		}

		return true
	})
	state := <-done

	if state.Error() != nil {
		log.Errorf("Error fetching object: %+v", state.Error())
		return
	}

	// statistics
	log.Infof("Object fetched: %s", state.Name())
	log.Infof("Content: %d bytes", byteCount)
	log.Infof("Time taken: %s", t2.Sub(t1))
	log.Infof("Throughput: %f Mbit/s", float64(byteCount*8)/t2.Sub(t1).Seconds()/1e6)
}
