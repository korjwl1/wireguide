package main

// GreetService is a minimal service for testing Go <-> Svelte bindings.
type GreetService struct{}

func (g *GreetService) Greet(name string) string {
	return "Hello " + name + "! WireGuide is ready."
}
