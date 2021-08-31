// plugin-node-resolve and plugin-commonjs are required for a rollup bundled project
// to resolve dependencies from node_modules. See the documentation for these plugins
// for more details.
import { nodeResolve } from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import yaml from 'rollup-plugin-yaml'

export default {
  input: 'src/main.mjs',
  output: {
    exports: 'named',
    format: 'es',
    file: 'dist/main.mjs',
    sourcemap: false,
  },
  plugins: [yaml(), commonjs(), nodeResolve({ browser: true })],
}
