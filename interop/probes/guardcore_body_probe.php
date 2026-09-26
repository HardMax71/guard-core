<?php

declare(strict_types=1);

/**
 * Body-surface probe for the interop extraction differential and body
 * detect vector runners (interop/extraction_differential.py and
 * interop/body_detect_vectors.py in the guard-core reference checkout).
 *
 * The file is NOT part of the repository: the runners mount it into the
 * checkout inside the php container (docker -v probe.php:/app/bin/
 * guardcore_body_probe.php), so the audited detection code is exactly
 * master and nothing is written to the working tree.
 *
 * Modes (env-selected):
 *
 *   INTEROP_EXTRACTION_INPUT / _OUTPUT: BodyFormScan::bodyScanEntries per
 *   body, emitted in scan order as [[value_b64, context, forced], ...].
 *   Values are base64 of the RAW BYTES (PHP strings are byte strings).
 *
 *   INTEROP_BODY_DETECT_INPUT / _OUTPUT: the SuspiciousActivityCheck scan
 *   loop (bodyScanEntries + SusPatterns::detect per entry, first enabled
 *   categories union) emitting is_threat plus categories.
 *
 *   INTEROP_MIDDLEWARE_INPUT / _OUTPUT: the real SuspiciousActivityCheck
 *   built like the pipeline builds it, check() on a SimpleGuardRequest,
 *   emitting blocked plus the status code.
 */

use RenzoFranceschini\GuardCore\Ban\IpBanManager;
use RenzoFranceschini\GuardCore\Config\SecurityConfig;
use RenzoFranceschini\GuardCore\Detection\BodyFormScan;
use RenzoFranceschini\GuardCore\Detection\SusPatterns;
use RenzoFranceschini\GuardCore\Pipeline\Checks\SuspiciousActivityCheck;
use RenzoFranceschini\GuardCore\Request\GuardResponseFactory;
use RenzoFranceschini\GuardCore\Request\RequestState;
use RenzoFranceschini\GuardCore\Request\SimpleGuardRequest;
use RenzoFranceschini\GuardCore\Routing\RouteResolver;

require __DIR__ . '/../vendor/autoload.php';

/**
 * @return list<array{label: string, body_b64: string, content_type: string, query: array<string, string>, url_path: string}>
 */
function readVectors(string $envKey): array
{
    $path = (string) getenv($envKey);
    if ($path === '') {
        fwrite(STDERR, "{$envKey} must be set\n");
        exit(1);
    }
    $raw = file_get_contents($path);
    if ($raw === false) {
        fwrite(STDERR, "cannot read {$path}\n");
        exit(1);
    }
    /** @var list<array{label: string, body_b64: string, content_type: string, query?: array<string, string>, url_path?: string}> $vectors */
    $vectors = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);

    return $vectors;
}

function writeOutput(string $envKey, mixed $payload): void
{
    $path = (string) getenv($envKey);
    if ($path === '') {
        fwrite(STDERR, "{$envKey} must be set\n");
        exit(1);
    }
    file_put_contents($path, json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

function probeConfig(): SecurityConfig
{
    return new SecurityConfig(
        enableIpBanning: true,
        autoBanThreshold: 100,
        autoBanDuration: 600
    );
}

/**
 * @return list<array{string, string, ?string}>
 */
function readBody(string $bodyB64, string $contentType): array
{
    return BodyFormScan::bodyScanEntries(base64_decode($bodyB64), $contentType, 16);
}

$mode = getenv('INTEROP_EXTRACTION_INPUT') !== false
    ? 'extraction'
    : (getenv('INTEROP_BODY_DETECT_INPUT') !== false
        ? 'detect'
        : (getenv('INTEROP_MIDDLEWARE_INPUT') !== false ? 'middleware' : ''));

switch ($mode) {
    case 'extraction':
        $out = [];
        foreach (readVectors('INTEROP_EXTRACTION_INPUT') as $vector) {
            $entries = [];
            foreach (readBody($vector['body_b64'], $vector['content_type']) as [$value, $context, $forced]) {
                $entries[] = [
                    'v' => base64_encode($value),
                    'c' => $context,
                    'f' => $forced ?? '',
                ];
            }
            $out[] = ['label' => $vector['label'], 'entries' => $entries];
        }
        writeOutput('INTEROP_EXTRACTION_OUTPUT', $out);
        break;

    case 'detect':
        $config = probeConfig();
        $susPatterns = new SusPatterns();
        $out = [];
        foreach (readVectors('INTEROP_BODY_DETECT_INPUT') as $vector) {
            // Mirrors SuspiciousActivityCheck::check's scan loop exactly:
            // every entry scans, forced hits report straight from the walk,
            // and enabled categories union across values.
            $categories = [];
            foreach (readBody($vector['body_b64'], $vector['content_type']) as [$value, $context, $forced]) {
                if ($forced !== null) {
                    if (isset($config->enabledDetectionCategories[$forced])
                        && !in_array($forced, $categories, true)
                    ) {
                        $categories[] = $forced;
                    }
                    continue;
                }
                $result = $susPatterns->detect($value, '127.0.0.1', $context);
                if (!$result['is_threat']) {
                    continue;
                }
                foreach ($result['threats'] as $threat) {
                    $category = $threat['category'] ?? 'custom';
                    if (!in_array($category, $categories, true)
                        && isset($config->enabledDetectionCategories[$category])
                    ) {
                        $categories[] = $category;
                    }
                }
            }
            sort($categories);
            $out[] = [
                'label' => $vector['label'],
                'is_threat' => $categories !== [],
                'categories' => $categories,
            ];
        }
        writeOutput('INTEROP_BODY_DETECT_OUTPUT', $out);
        break;

    case 'middleware':
        $config = probeConfig();
        $check = new SuspiciousActivityCheck(
            $config,
            new GuardResponseFactory(),
            new SusPatterns(),
            new IpBanManager(),
            new RouteResolver()
        );
        $out = [];
        foreach (readVectors('INTEROP_MIDDLEWARE_INPUT') as $vector) {
            $body = base64_decode($vector['body_b64']);
            $state = new RequestState();
            $state->clientIp = '203.0.113.9';
            $request = new SimpleGuardRequest(
                $vector['url_path'] !== '' ? $vector['url_path'] : '/api',
                'http',
                'example.com',
                'POST',
                '203.0.113.9',
                ['content-type' => $vector['content_type']],
                $vector['query'] ?? [],
                '',
                $body,
                null,
                $state
            );
            $response = $check->check($request);
            $out[] = [
                'label' => $vector['label'],
                'blocked' => $response !== null,
                'status' => $response !== null ? $response->statusCode() : 0,
            ];
        }
        writeOutput('INTEROP_MIDDLEWARE_OUTPUT', $out);
        break;

    default:
        fwrite(STDERR, "no probe mode selected\n");
        exit(1);
}
