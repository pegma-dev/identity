# Contributing

Read [AGENTS.md](AGENTS.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before changing the package.
Pull requests must pass the complete gate on Node.js 22 and 24:

```sh
npm ci
npm run format:check
npm run check
npm test
npm audit --omit=dev --audit-level=high
```

`npm test` starts Azurite. Identity uniqueness, repair, challenge consumption,
and counter transitions must agree between the memory store and the real
adapter where storage races are involved.
