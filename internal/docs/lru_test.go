package docs

import "testing"

func TestLRUBasic(t *testing.T) {
	l := NewLRU(2)
	l.Put("a", 1)
	l.Put("b", 2)
	if v, ok := l.Get("a"); !ok || v.(int) != 1 {
		t.Errorf("a: %v %v", v, ok)
	}
	l.Put("c", 3) // evicts b
	if _, ok := l.Get("b"); ok {
		t.Error("b should have been evicted")
	}
	if l.Len() != 2 {
		t.Errorf("len: %d", l.Len())
	}
}

func TestLRUUpdate(t *testing.T) {
	l := NewLRU(3)
	l.Put("a", 1)
	l.Put("a", 2)
	if v, _ := l.Get("a"); v.(int) != 2 {
		t.Errorf("update: %v", v)
	}
	if l.Len() != 1 {
		t.Errorf("len: %d", l.Len())
	}
}

func TestLRUZeroCapacity(t *testing.T) {
	l := NewLRU(0) // defaults to 256
	if l.capacity != 256 {
		t.Errorf("default capacity: %d", l.capacity)
	}
}
