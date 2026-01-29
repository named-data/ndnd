package io

import (
	"bufio"
	"io"
	"sync"
	"time"
)

// TimedWriter is a buffered writer that flushes automatically
// when a deadline is set and the deadline is exceeded.
type TimedWriter struct {
	*bufio.Writer
	mutex    sync.Mutex
	deadline time.Duration
	maxQueue int

	queueSize int
	timer     *time.Timer
	prevErr   error
}

// (AI GENERATED DESCRIPTION): Creates a TimedWriter that wraps the supplied io.Writer in a buffered writer of the given size and initializes it with a 1‑millisecond deadline and a maximum flush queue of 8.
func NewTimedWriter(io io.Writer, bufsize int) *TimedWriter {
	return &TimedWriter{
		Writer:   bufio.NewWriterSize(io, bufsize),
		deadline: 1 * time.Millisecond,
		maxQueue: 8,
	}
}

// (AI GENERATED DESCRIPTION): Sets the deadline duration that the TimedWriter will use for its timed operations.
func (w *TimedWriter) SetDeadline(d time.Duration) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.deadline = d
}

// (AI GENERATED DESCRIPTION): Sets the maximum number of packets the TimedWriter can buffer in its internal queue.
func (w *TimedWriter) SetMaxQueue(s int) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.maxQueue = s
}

// (AI GENERATED DESCRIPTION): Flush acquires the TimedWriter’s mutex, invokes its internal flush routine, and returns any error that occurs.
func (w *TimedWriter) Flush() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.flush_()
}

// (AI GENERATED DESCRIPTION): Writes data to the underlying writer, buffering until the queued size reaches the maximum or the deadline expires, then flushes the buffer (or returns any stored previous error) while ensuring thread‑safety.
func (w *TimedWriter) Write(p []byte) (n int, err error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if err := w.prevErr; err != nil {
		w.prevErr = nil
		return 0, err
	}

	n, err = w.Writer.Write(p)
	if err != nil {
		return n, err
	}

	w.queueSize++
	if w.deadline == 0 || w.queueSize >= w.maxQueue {
		return n, w.flush_()
	}

	if w.timer == nil {
		w.timer = time.AfterFunc(w.deadline, func() { w.Flush() })
	}

	return
}

// (AI GENERATED DESCRIPTION): Flushes the underlying writer, stops the timer if active, clears the queued byte count, and records any error that occurs during the flush.
func (w *TimedWriter) flush_() error {
	err := w.Writer.Flush()
	if err != nil {
		w.prevErr = err
	}

	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	w.queueSize = 0

	return err
}
