#!/usr/bin/env node
/**
 * MCP Filesystem Server (JavaScript/Node.js)
 *
 * Functionally equivalent to the Python filesystem_server.py.
 * Tools: read_file, write_file, list_dir.
 * Communicates via JSON-RPC 2.0 over stdin/stdout.
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const WORKSPACE = process.env.MCP_WORKSPACE || './workspace';

const tools = {
  read_file: {
    description: 'Read the contents of a file',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'File path' }
      }
    },
    handler(args) {
      const filePath = args.path || '';
      let target;
      if (path.isAbsolute(filePath)) {
        target = filePath;
      } else {
        target = path.resolve(WORKSPACE, filePath);
      }
      const content = fs.readFileSync(target, 'utf-8');
      return { path: target, content };
    }
  },
  write_file: {
    description: 'Write content to a file',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'File path' },
        content: { type: 'string', description: 'Content to write' }
      }
    },
    handler(args) {
      const filePath = args.path || '';
      const content = args.content || '';
      let target;
      if (path.isAbsolute(filePath)) {
        target = filePath;
      } else {
        target = path.resolve(WORKSPACE, filePath);
      }
      const dir = path.dirname(target);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(target, content, 'utf-8');
      return { path: target, written: true, bytes: content.length };
    }
  },
  list_dir: {
    description: 'List directory contents',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Directory path' }
      }
    },
    handler(args) {
      const dirPath = args.path || '.';
      const target = path.resolve(WORKSPACE, dirPath);
      const entries = fs.readdirSync(target, { withFileTypes: true }).map(e => ({
        name: e.name,
        type: e.isDirectory() ? 'directory' : 'file',
        size: e.isFile() ? fs.statSync(path.join(target, e.name)).size : 0
      }));
      return { path: target, entries };
    }
  }
};

function dispatch(request) {
  const { method, params, id } = request;

  if (method === 'initialize') {
    return {
      jsonrpc: '2.0', id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'js-filesystem-server', version: '1.0.0' }
      }
    };
  }

  if (method === 'notifications/initialized') return null;

  if (method === 'tools/list') {
    return {
      jsonrpc: '2.0', id,
      result: {
        tools: Object.entries(tools).map(([name, t]) => ({
          name, description: t.description, inputSchema: t.inputSchema
        }))
      }
    };
  }

  if (method === 'tools/call') {
    const toolName = params.name;
    const args = params.arguments || {};
    if (!tools[toolName]) {
      return {
        jsonrpc: '2.0', id,
        result: { isError: true, content: [{ type: 'text', text: `Unknown tool: ${toolName}` }] }
      };
    }
    try {
      const result = tools[toolName].handler(args);
      return {
        jsonrpc: '2.0', id,
        result: { content: [{ type: 'text', text: JSON.stringify(result) }] }
      };
    } catch (err) {
      return {
        jsonrpc: '2.0', id,
        result: { isError: true, content: [{ type: 'text', text: `Tool error: ${err.message}` }] }
      };
    }
  }

  return {
    jsonrpc: '2.0', id,
    error: { code: -32601, message: `Method not found: ${method}` }
  };
}

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  try {
    const request = JSON.parse(line.trim());
    const response = dispatch(request);
    if (response) {
      process.stdout.write(JSON.stringify(response) + '\n');
    }
  } catch (err) {
    process.stdout.write(JSON.stringify({
      jsonrpc: '2.0', id: null,
      error: { code: -32700, message: `Parse error: ${err.message}` }
    }) + '\n');
  }
});
