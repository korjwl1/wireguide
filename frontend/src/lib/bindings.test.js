import { test } from 'node:test';
import assert from 'node:assert/strict';
import { register } from 'node:module';

const createURL = new URL('./create.js', import.meta.resolve('@wailsio/runtime')).href;
const modelRuntime = 'data:text/javascript,' + encodeURIComponent(`export * as Create from ${JSON.stringify(createURL)};`);
register('data:text/javascript,' + encodeURIComponent(`
  export async function resolve(specifier, context, next) {
    if (specifier === '@wailsio/runtime') return { url: ${JSON.stringify(modelRuntime)}, shortCircuit: true };
    return next(specifier, context);
  }
`), import.meta.url);

const models = await import('../../bindings/github.com/korjwl1/wireguide/internal/app/models.js');
const config = await import('../../bindings/github.com/korjwl1/wireguide/internal/config/models.js');

test('combined generated bindings preserve DNS domain arrays and DNS server models', () => {
  const tunnel = models.TunnelInfo.createFrom({ name: 'work', dns_domains: ['corp.example', 'internal.example'] });
  assert.deepEqual(tunnel.dns_domains, ['corp.example', 'internal.example']);
  assert.equal(tunnel.dns_domains.join(', '), 'corp.example, internal.example');
  const result = models.DNSLeakResult.createFrom({ dns_servers: [{ ip: '1.1.1.1' }] });
  assert.ok(result.dns_servers[0] instanceof models.DNSServer);
  assert.equal(result.dns_servers[0].ip, '1.1.1.1');
});

test('combined generated bindings preserve automation verdict and lint-fix models', () => {
  const preview = models.AutomationPreview.createFrom({ available: true, tunnels: [{ name: 'work', verdict: 'connect' }] });
  assert.ok(preview.tunnels[0] instanceof models.AutomationVerdict);
  assert.equal(preview.tunnels[0].name, 'work');
  const diagnostic = config.Diagnostic.createFrom({ field: 'Interface.DNS', args: { value: 'x' }, fix: { action: 'remove_dns' } });
  assert.ok(diagnostic.fix instanceof config.Fix);
  assert.equal(diagnostic.fix.action, 'remove_dns');
  assert.equal(diagnostic.args.value, 'x');
});
