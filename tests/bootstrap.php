<?php declare(strict_types=1);

/**
 * Test bootstrap.
 *
 * The plugin class extends rcube_plugin, so that base class must be loadable.
 * We only need the (dependency-free) base class, not a full Roundcube runtime,
 * so the pure logic can be tested without a database or config.
 *
 * Roundcube is located via (in order):
 *   1. the RCUBE_INSTALL_PATH environment variable
 *   2. an in-tree install (plugin sitting at <roundcube>/plugins/f2b)
 *   3. a sibling checkout (../roundcubemail)
 */

$rcube_plugin = 'program/lib/Roundcube/rcube_plugin.php';

$candidates = array_filter([
    getenv('RCUBE_INSTALL_PATH') ?: null,
    dirname(__DIR__, 3),               // <roundcube>/plugins/f2b/tests -> <roundcube>
    dirname(__DIR__, 2) . '/roundcubemail',
]);

$base = null;
foreach ($candidates as $path) {
    if (is_file(rtrim($path, '/') . '/' . $rcube_plugin)) {
        $base = rtrim($path, '/');
        break;
    }
}

if ($base === null) {
    fwrite(STDERR, "Could not locate the Roundcube framework.\n"
        . "Set RCUBE_INSTALL_PATH to your Roundcube root directory.\n");
    exit(1);
}

require_once $base . '/' . $rcube_plugin;
require_once dirname(__DIR__) . '/f2b.php';
