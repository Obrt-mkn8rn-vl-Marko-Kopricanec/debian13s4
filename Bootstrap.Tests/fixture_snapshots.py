"""Lossless text objects for the private bootstrap crash model, not real storage."""

import hashlib
import os
from pathlib import Path
import re


class SnapshotStore:
    TAG = '$bootstrap_text'
    SCOPES = ('state', 'boot', 'library', 'units')

    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700, exist_ok=True)

    def text(self, value):
        if not isinstance(value, str):
            raise ValueError('snapshot file content must be text')
        data = value.encode('utf-8')
        digest = hashlib.sha256(data).hexdigest()
        path = self.directory / digest
        try:
            with path.open('xb') as stream:
                stream.write(data)
        except FileExistsError:
            if path.read_bytes() != data:
                raise ValueError('snapshot object changed')
        return {self.TAG: digest}

    def compact_state(self, state):
        for scope in self.SCOPES:
            state['disk'][scope] = {name: self.text(value) if isinstance(value, str) else value
                                   for name, value in state['disk'][scope].items()}
        return state

    def files(self, directory):
        """Fresh visible file contents, without descending excluded staging trees.

        No metadata/content/trust result survives this invocation. The original
        model excluded every path with a bundle.* component after walking it;
        pruning those subtrees preserves that exclusion without the traversal.
        """
        directory = Path(directory)
        if any(part.startswith('bundle.') for part in directory.parts):
            return {}
        result = {}
        for parent, directories, filenames in os.walk(directory, followlinks=False):
            directories[:] = [name for name in directories if not name.startswith('bundle.')]
            for name in filenames:
                if name.startswith('bundle.'):
                    continue
                path = Path(parent) / name
                if path.is_file() and not path.is_symlink():
                    result[str(path.relative_to(directory))] = self.text(path.read_text())
        return result

    def expand(self, value, cache=None):
        if cache is None:
            cache = {}
        if isinstance(value, dict):
            if self.TAG in value:
                digest = value[self.TAG]
                if set(value) != {self.TAG} or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
                    raise ValueError('invalid snapshot reference')
                if digest not in cache:
                    data = (self.directory / digest).read_bytes()
                    if hashlib.sha256(data).hexdigest() != digest:
                        raise ValueError('corrupt snapshot object')
                    cache[digest] = data.decode('utf-8')
                return cache[digest]
            return {name: self.expand(item, cache) for name, item in value.items()}
        if isinstance(value, list):
            return [self.expand(item, cache) for item in value]
        return value
