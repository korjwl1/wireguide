package helper

import "context"

// Setup work belongs to the helper lifetime even when it was started by
// automation or crash restoration rather than a cancellable GUI request.
func (h *Helper) operationContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	if h.done != nil {
		go func() {
			select {
			case <-h.done:
				cancel()
			case <-ctx.Done():
			}
		}()
	}
	return ctx, cancel
}
