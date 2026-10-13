//go:build !darwin

package gui

import "sync"

func startGUIHangMonitor(string, <-chan struct{}, *sync.WaitGroup) {}
