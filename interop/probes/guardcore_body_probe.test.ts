/**
 * Body-surface probe for the interop extraction differential and body
 * detect vector runners (interop/extraction_differential.py and
 * interop/body_detect_vectors.py in the guard-core reference checkout).
 *
 * The file is NOT part of the repository: the runner copies it into the
 * checkout's packages/core/tests/interop/ directory (a disposable clone),
 * so the audited detection code is exactly master.
 *
 * Modes (env-selected, see GUARDCORE_PROBE_MODE):
 *
 *   extraction: scanRequestWithManager over a RECORDING fake manager (every
 *   detect call is one extracted scan value; the engine itself builds the
 *   list, so no extraction logic is reimplemented here). Forced mongo
 *   operator keys terminate the walk inside scanJsonKey without a detect
 *   call and are recovered from the returned trigger message.
 *
 *   pipeline: the real initializeSecurityMiddleware pipeline executed end
 *   to end on each request (blocked plus status), used for the body detect
 *   vectors and the middleware-level spot checks.
 *
 * Values are emitted base64(UTF-8) via the JSON report file.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, writeFileSync } from 'node:fs';
import { scanRequestWithManager } from '../../src/utils.js';
import { initializeSecurityMiddleware } from '../../src/middleware-support.js';
import type { SecurityMiddlewareComponents } from '../../src/middleware-support.js';
import { SecurityConfigSchema } from '../../src/models/config.js';
import { defaultLogger } from '../../src/models/logger.js';
import type { GuardRequest } from '../../src/protocols/request.js';
import { createMockResponseFactory } from '../helpers.js';
import type { SusPatternsManager } from '../../src/handlers/sus-patterns.js';

interface ProbeVector {
  label: string;
  body_b64: string;
  content_type: string;
  query?: Record<string, string>;
  url_path?: string;
}

interface ProbeEntry {
  v: string;
  c: string;
  f: string;
}

const inputPath = process.env.GUARDCORE_PROBE_INPUT ?? '';
const outputPath = process.env.GUARDCORE_PROBE_OUTPUT ?? '';
const mode = process.env.GUARDCORE_PROBE_MODE ?? '';

function readVectors(): ProbeVector[] {
  if (!inputPath) throw new Error('GUARDCORE_PROBE_INPUT must be set');
  return JSON.parse(readFileSync(inputPath, 'utf8')) as ProbeVector[];
}

function makeRequest(vector: ProbeVector): GuardRequest {
  const urlPath = vector.url_path && vector.url_path !== '' ? vector.url_path : '/api';
  const bytes = Buffer.from(vector.body_b64, 'base64');
  return {
    urlPath,
    urlScheme: 'http',
    urlFull: `http://example.com${urlPath}`,
    urlReplaceScheme: (s: string) => `${s}://example.com${urlPath}`,
    method: 'POST',
    clientHost: '203.0.113.9',
    headers: { 'content-type': vector.content_type },
    queryParams: vector.query ?? {},
    body: async () => new Uint8Array(bytes),
    state: {},
    scope: {},
  };
}

describe('guardcore body probe', () => {
  it(
    mode === 'pipeline'
      ? 'runs the real middleware pipeline'
      : 'records the extraction surface through a fake manager',
    async () => {
      const vectors = readVectors();
      const results: Array<Record<string, unknown>> = [];

      if (mode === 'pipeline') {
        const config = SecurityConfigSchema.parse({
          enableRedis: false,
          enableRateLimiting: false,
          autoBanThreshold: 100,
        });
        const components: SecurityMiddlewareComponents =
          await initializeSecurityMiddleware(config, defaultLogger, createMockResponseFactory());
        for (const vector of vectors) {
          const response = await components.pipeline.execute(makeRequest(vector));
          results.push({
            label: vector.label,
            blocked: response !== null && response !== undefined,
            status: response ? response.statusCode : 0,
          });
        }
      } else {
        for (const vector of vectors) {
          const recorded: ProbeEntry[] = [];
          const fakeManager = {
            detectionBinaryMinRunLength: 16,
            detect: async (value: string, _ip: string, context: string) => {
              if (context.startsWith('request_body')) {
                recorded.push({
                  v: Buffer.from(value, 'utf8').toString('base64'),
                  c: context,
                  f: '',
                });
              }
              return { isThreat: false, threats: [] };
            },
          } as unknown as SusPatternsManager;
          const [blocked, message] = await scanRequestWithManager(
            fakeManager,
            makeRequest(vector),
          );
          if (blocked) {
            const match = /JSON operator key '(.*)': matched pattern/.exec(message);
            if (match !== null) {
              recorded.push({ v: Buffer.from(match[1], 'utf8').toString('base64'), c: 'request_body', f: 'nosql' });
            } else {
              throw new Error(`unexpected block in extraction mode: ${message}`);
            }
          }
          results.push({ label: vector.label, entries: recorded });
        }
      }

      if (!outputPath) throw new Error('GUARDCORE_PROBE_OUTPUT must be set');
      writeFileSync(outputPath, JSON.stringify(results, null, 2));
      expect(results).toHaveLength(vectors.length);
    },
  );
});
