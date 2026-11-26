//go:build windows

package tunnel

import "errors"

type kernelIntentLock struct{}

func tryLockKernelIntent(string) (*kernelIntentLock, error) {
	return nil, errors.New("kernel link intents are not used on Windows")
}

func (*kernelIntentLock) unlock() {}
