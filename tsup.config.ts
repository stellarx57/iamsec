import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'core/index': 'src/core/index.ts',
    'hooks/index': 'src/hooks/index.ts',
    'guards/index': 'src/guards/index.ts',
    'middleware/index': 'src/middleware/index.ts',
    'providers/index': 'src/providers/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  minify: false,
  external: ['react', 'react-dom', 'next', '@mui/material', 'js-cookie'],
  esbuildOptions(options) {
    options.banner = {
      js: '"use client";',
    };
  },
});

