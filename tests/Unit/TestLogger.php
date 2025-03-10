<?php

namespace Tests\Unit;

use Psr\Log\AbstractLogger;

class TestLogger extends AbstractLogger
{
    public array $logs = [];

    /**
     * @inheritDoc
     */
    public function log($level, \Stringable|string $message, array $context = []): void
    {
        $this->logs[] = compact('level', 'message', 'context');
    }
}