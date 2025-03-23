package channel

import (
	"fmt"
	"sync"
)

// Window represents the SSH flow control window
type Window struct {
	size    uint32 // Current window size
	maxSize uint32 // Maximum window size
	minSize uint32 // Minimum window size for auto-adjustment
	mu      sync.Mutex
}

// NewWindow creates a new flow control window
func NewWindow(initialSize, maxSize uint32) *Window {
	// Minimum window size for adjustment is 25% of max
	minSize := maxSize / 4

	return &Window{
		size:    initialSize,
		maxSize: maxSize,
		minSize: minSize,
	}
}

// Add increases the window size
func (w *Window) Add(n uint32) uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check for overflow
	if w.size+n < w.size {
		w.size = w.maxSize // Reset to max on overflow
	} else if w.size+n > w.maxSize {
		w.size = w.maxSize // Cap at max
	} else {
		w.size += n
	}

	return w.size
}

// Consume decreases the window size
func (w *Window) Consume(n uint32) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if n > w.size {
		return fmt.Errorf("cannot consume %d bytes, only %d available", n, w.size)
	}

	w.size -= n
	return nil
}

// Available returns the current available window size
func (w *Window) Available() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.size
}

// NeedsAdjustment checks if the window needs adjustment
func (w *Window) NeedsAdjustment() bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.size < w.minSize
}

// AdjustmentSize calculates the size to add for adjustment
func (w *Window) AdjustmentSize() uint32 {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Calculate how much to add to get back to max
	return w.maxSize - w.size
}
