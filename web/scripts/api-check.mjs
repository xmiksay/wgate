// Fails when src/api/schema.d.ts is stale against ../docs/openapi.json (`npm run api:gen`).
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const dir = mkdtempSync(join(tmpdir(), 'wgate-api-'))
const fresh = join(dir, 'schema.d.ts')
try {
  execFileSync('openapi-typescript', ['../docs/openapi.json', '-o', fresh], { stdio: 'ignore' })
  if (readFileSync(fresh, 'utf8') !== readFileSync('src/api/schema.d.ts', 'utf8')) {
    console.error('src/api/schema.d.ts is stale: run `npm run api:gen`')
    process.exitCode = 1
  }
} finally {
  rmSync(dir, { recursive: true, force: true })
}
