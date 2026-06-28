package docs

import (
	"container/list"
	"sync"
)

// LRU is a fixed-capacity LRU cache. Eviction is FIFO. It is safe for
// concurrent use.
type LRU struct {
	mu       sync.Mutex
	capacity int
	items    map[string]*list.Element
	order    *list.List
}

type lruEntry struct {
	key   string
	value any
}

// NewLRU creates a new LRU with the given capacity. If capacity is
// <= 0 it defaults to 256.
func NewLRU(capacity int) *LRU {
	if capacity <= 0 {
		capacity = 256
	}
	return &LRU{
		capacity: capacity,
		items:    make(map[string]*list.Element),
		order:    list.New(),
	}
}

// Get returns the value for a key and true if present.
func (l *LRU) Get(key string) (any, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		l.order.MoveToFront(el)
		return el.Value.(*lruEntry).value, true
	}
	return nil, false
}

// Put inserts or updates a key.
func (l *LRU) Put(key string, value any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if el, ok := l.items[key]; ok {
		el.Value.(*lruEntry).value = value
		l.order.MoveToFront(el)
		return
	}
	el := l.order.PushFront(&lruEntry{key: key, value: value})
	l.items[key] = el
	if l.order.Len() > l.capacity {
		// Evict oldest
		old := l.order.Back()
		if old != nil {
			l.order.Remove(old)
			delete(l.items, old.Value.(*lruEntry).key)
		}
	}
}

// Len returns the current number of items.
func (l *LRU) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.order.Len()
}

// Clear empties the cache.
func (l *LRU) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.items = make(map[string]*list.Element)
	l.order.Init()
}
