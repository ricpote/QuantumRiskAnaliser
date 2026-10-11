"""Start API + TanStack dev/production server and stop both on exit."""
from __future__ import annotations
import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parent.parent

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--production', action='store_true')
    parser.add_argument('--lab', action='store_true')
    parser.add_argument('--port', type=int, default=8501)
    parser.add_argument('--results', default=os.environ.get('QT_RESULTS_DIR', str(ROOT / 'out')))
    args = parser.parse_args()
    node = shutil.which('node')
    if not node:
        parser.error('Node.js 24 is required')
    frontend = ROOT / 'frontend'
    entry = frontend / ('.output/server/index.mjs' if args.production else 'node_modules/vite/bin/vite.js')
    if not entry.exists():
        parser.error('Run npm ci in frontend/' + (' and npm run build' if args.production else ''))
    env = dict(os.environ, PORT=str(args.port), HOST='0.0.0.0' if args.production else '127.0.0.1')
    env['QT_API_ORIGIN'] = 'http://127.0.0.1:8502'
    children = []
    def stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        children.append(subprocess.Popen([sys.executable, '-m', 'quantumtrace.web', '--results', args.results], cwd=ROOT, env=env))
        if args.lab:
            for binary in ('tlslab-modern', 'tlslab-legacy'):
                children.append(subprocess.Popen([binary], env=env))
        cmd = [node, str(entry)]
        if not args.production:
            cmd += ['--host', '127.0.0.1', '--port', str(args.port)]
        children.append(subprocess.Popen(cmd, cwd=frontend, env=env))
        while all(child.poll() is None for child in children):
            time.sleep(0.3)
        return next((child.returncode or 1 for child in children if child.poll() is not None), 1)
    except KeyboardInterrupt:
        return 0
    finally:
        for child in children:
            if child.poll() is None:
                child.terminate()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()

if __name__ == '__main__':
    sys.exit(main())
