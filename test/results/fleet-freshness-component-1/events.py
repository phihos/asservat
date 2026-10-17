"""Strict saved-output checks for the fixed full-Go qualification runner."""
from collections import Counter, defaultdict
import json
import re

NAME = re.compile(r'(?:Test|Fuzz|Example)[A-Za-z0-9_]*\Z')
TERMINAL = {'pass', 'skip', 'fail'}


def json_values(text):
    values, decoder = [], json.JSONDecoder()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        values.append(value)
        text = text.lstrip()[end:]
    return values


def events(text):
    for line in text.splitlines():
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError('non-object Go event')
        if value.get('Action') in ('fail', 'build-fail'):
            raise ValueError('failing Go event')
        if value.get('Action') == 'build-output' and isinstance(value.get('ImportPath'), str):
            continue
        if not isinstance(value.get('Package'), str):
            raise ValueError('event has no package')
        yield value


def source_declarations(text):
    names = []
    for match in re.finditer(r'^func ((?:Test|Fuzz)[A-Za-z0-9_]*)\(([^)]*)\)\s*\{', text, re.M):
        name, args = match.groups()
        if name.startswith('Test') and '*testing.T' in args or name.startswith('Fuzz') and '*testing.F' in args:
            names.append(name)
    # Examples without an Output directive are compiled but are not runnable.
    for match in re.finditer(r'^func (Example[A-Za-z0-9_]*)\(\)\s*\{(.*?)^}', text, re.M | re.S):
        if re.search(r'(?im)^\s*//\s*(?:unordered )?output:', match[2]):
            names.append(match[1])
    if len(names) != len(set(names)):
        raise ValueError('duplicate source test declaration')
    return names


def discovery(text, expected):
    """Compare actual go-test listing with selected source declarations per package."""
    names = defaultdict(list)
    starts, ends = Counter(), Counter()
    for event in events(text):
        package, action = event['Package'], event.get('Action')
        if package not in expected or event.get('Test'):
            raise ValueError('unexpected discovery package or executed test')
        if action == 'start':
            starts[package] += 1
        elif action in TERMINAL:
            if action == 'skip' and expected[package]:
                raise ValueError('discovery skipped declared tests')
            ends[package] += 1
        elif action == 'output':
            for line in event.get('Output', '').splitlines():
                if NAME.fullmatch(line):
                    names[package].append(line)
        else:
            raise ValueError('unexpected discovery event')
    if starts != Counter(expected.keys()) or ends != Counter(expected.keys()):
        raise ValueError('discovery package starts/terminals incomplete or duplicate')
    for package, wanted in expected.items():
        if Counter(names[package]) != Counter(wanted):
            raise ValueError('discovered names differ from selected source: ' + package)
    return {p: sorted(names[p]) for p in expected}


def partition(names):
    if not names or len(set(names)) != len(names) or any(not NAME.fullmatch(n) for n in names):
        raise ValueError('invalid Kubernetes inventory')
    groups = [sorted(names)[i:i+80] for i in range(0, len(names), 80)]
    if Counter(n for group in groups for n in group) != Counter(names):
        raise ValueError('incomplete or overlapping groups')
    return groups


def execution(text, expected, allowed):
    """All parent and child runs terminate once; only exact documented skips pass."""
    starts, terminals, runs, done = Counter(), Counter(), Counter(), Counter()
    outcomes, output, skips = {}, defaultdict(list), []
    for event in events(text):
        package, action, name = event['Package'], event.get('Action'), event.get('Test')
        if package not in expected:
            raise ValueError('unexpected execution package')
        if not name:
            if action == 'start':
                starts[package] += 1
            elif action in TERMINAL:
                if action == 'skip' and expected[package]:
                    raise ValueError('package skipped declared tests')
                terminals[package] += 1
            elif action != 'output':
                raise ValueError('unexpected package event')
            continue
        if not isinstance(name, str) or name.split('/')[0] not in expected[package]:
            raise ValueError('unselected test or child')
        key = (package, name)
        if action == 'run':
            if runs[key] or done[key]:
                raise ValueError('duplicate or late run')
            runs[key] += 1
        elif action in TERMINAL:
            if runs[key] != 1 or done[key]:
                raise ValueError('missing run or duplicate terminal')
            done[key] += 1
            outcomes[key] = action
            if action == 'skip':
                reason = allowed.get(key)
                if reason is None:
                    raise ValueError('unapproved skip: ' + package + '/' + name)
                # The original testing.T.Skip message must precede its terminal.
                pattern = r'(?m)^\s+[^\n]+_test\.go:\d+: ' + re.escape(reason) + r'\s*$'
                if not re.search(pattern, ''.join(output[key])):
                    raise ValueError('skip lacks exact documented fixture reason')
                skips.append({'package': package, 'test': name, 'reason': reason})
        elif action == 'output':
            output[key].append(event.get('Output', ''))
        elif action not in ('pause', 'cont'):
            raise ValueError('unexpected test event')
    wanted = Counter((p, n) for p, names in expected.items() for n in names)
    parents = Counter({key: count for key, count in runs.items() if '/' not in key[1]})
    if parents != wanted or runs != done:
        raise ValueError('parent selection or child completion differs from exact inventory')
    if starts != Counter(expected.keys()) or terminals != Counter(expected.keys()):
        raise ValueError('package starts/terminals incomplete or duplicate')
    return {'parents': len(wanted), 'namedTests': len(done), 'skips': skips,
            'passedParents': sorted(p + '/' + n for (p, n), result in outcomes.items()
                                    if '/' not in n and result == 'pass')}
