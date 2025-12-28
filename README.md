# Messpit

A cross-platform memory scanner and editor for macOS, Linux, and Windows. Built with Rust and Tauri.

> **Beta**: This project is under active development. Expect bugs and breaking changes.

## Features

- **Memory Scanning** - Search for values in process memory with support for multiple data types (integers, floats, strings, byte arrays)
- **Memory Editing** - Modify values in real-time
- **Pattern Scanning** - Find byte patterns with wildcards (AOB scanning)
- **Process Attachment** - Attach to running processes and enumerate memory regions/modules
- **Scripting** - JavaScript-based scripting with a built-in console and script management

## Platform Support

| Platform | Status |
|----------|--------|
| macOS    | Supported |
| Linux    | Supported |
| Windows  | Planned |

## Building

### Prerequisites

- [Rust](https://rustup.rs/) (latest stable)
- [Node.js](https://nodejs.org/) (v18+)
- [pnpm](https://pnpm.io/)

### Build

```bash
pnpm install
pnpm tauri build
```

### Development

```bash
pnpm tauri dev
```

## Usage

1. Launch Messpit
2. Select a process from the process list
3. Enter a value to search for and select the data type
4. Click "First Scan" to find matching addresses
5. Change the value in the target application
6. Enter the new value and click "Next Scan" to narrow results
7. Double-click an address to add it to the results table
8. Edit values directly in the results table

## License

MIT
