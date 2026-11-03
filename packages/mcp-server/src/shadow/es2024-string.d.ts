// ES2024 String methods the vendored Shadow profile uses (canonical() and clip()). Node 20 ships them (V8 11.3);
// the package's lib is ES2022, so declare them here rather than widening the lib for the whole package.
interface String {
  isWellFormed(): boolean;
  toWellFormed(): string;
}
