package accessportal

import (
	"context"

	"golang.org/x/sync/errgroup"
)

// Keep each resolve's fan-out small enough not to overwhelm FreeIPA. Results
// occupy their input index so concurrent completion never changes display order.
const queryConcurrency = 4

func queryBatch[T any](ctx context.Context, names []string, load func(context.Context, string) (T, error)) ([]T, error) {
	results := make([]T, len(names))
	g, queryCtx := errgroup.WithContext(ctx)
	g.SetLimit(queryConcurrency)
	for i, name := range names {
		g.Go(func() error {
			if err := queryCtx.Err(); err != nil {
				return err
			}
			var err error
			results[i], err = load(queryCtx, name)
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
