import { defineConfig } from 'vitest/config';

import { OrderedIntegrationSequencer } from './test-sequencer';

export default defineConfig({
  test: {
    fileParallelism: false,
    include: [
      'src/01-register-login-note.test.ts',
      'src/02-password-rotation.test.ts',
      'src/03-api-user.test.ts',
      'src/04-import-export-suite.test.ts',
    ],
    hookTimeout: 300_000,
    sequence: {
      sequencer: OrderedIntegrationSequencer,
      shuffle: false,
    },
    testTimeout: 180_000,
  },
});