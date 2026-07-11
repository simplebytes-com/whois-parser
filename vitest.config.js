import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        globals: true,
        environment: 'node',
        include: ['test/**/*.test.js'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json', 'html'],
            include: ['whois-parser.js', 'status-codes.js', 'field-mappings.js'],
        },
        testTimeout: 10000,
    },
});
