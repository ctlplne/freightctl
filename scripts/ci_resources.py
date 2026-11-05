"""S004: shared-machine defaults stay local; GitHub uses runner capacity."""
import re


def environment(values):
    result = dict(values)
    if result.get('GITHUB_ACTIONS') != 'true':
        return result
    result.pop('GOMAXPROCS', None)
    result.pop('GOMEMLIMIT', None)
    if 'NODE_OPTIONS' in result:
        options = re.sub(r'(?<!\S)--max-old-space-size(?:=|\s+)\S+', '', result['NODE_OPTIONS']).strip()
        if options:
            result['NODE_OPTIONS'] = options
        else:
            result.pop('NODE_OPTIONS')
    return result
