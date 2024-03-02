package contextutil

import (
	"context"
)

const (
	SourceTag  = "source"
	InboundTag = "inbound"
)

func WithSourceAndInboundValues(ctx context.Context, sourceAddr, inbound string) context.Context {
	return WithValues(ctx, SourceTag, sourceAddr, InboundTag, inbound)
}

func WithValues(ctx context.Context, kv ...interface{}) context.Context {
	if len(kv)%2 != 0 {
		panic("odd numbers of key-value pairs")
	}
	for i := range len(kv) / 2 {
		ctx = context.WithValue(ctx, kv[i*2], kv[i*2+1])
	}
	return ctx
}
