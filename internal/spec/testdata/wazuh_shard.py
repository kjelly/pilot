"""Optional sharding for slow Wazuh harnesses. Importing this module has no side effects."""

def run_tests():
    """Run the calling harness module; with PILOT_WAZUH_SHARD=i/n run only shard i of n.

    A test belongs to a shard by the CRC-32 of its id, so the partition is stable and
    every test lands in exactly one shard. Each shard prints `SHARD i/n: k of TOTAL tests`
    so the Go side can prove the shards together ran every test. Without the variable this
    is exactly unittest.main(verbosity=2).
    """
    import os
    import sys
    import unittest
    import zlib
    module = sys.modules['__main__']
    spec = os.environ.get('PILOT_WAZUH_SHARD', '')
    if not spec:
        unittest.main(module=module, verbosity=2)
        return
    index, count = (int(part) for part in spec.split('/'))
    if not 0 <= index < count:
        raise SystemExit('invalid PILOT_WAZUH_SHARD ' + spec)

    def flatten(suite):
        for item in suite:
            if isinstance(item, unittest.TestSuite):
                yield from flatten(item)
            else:
                yield item
    tests = list(flatten(unittest.defaultTestLoader.loadTestsFromModule(module)))
    mine = [test for test in tests if zlib.crc32(test.id().encode()) % count == index]
    print('SHARD %d/%d: %d of %d tests' % (index, count, len(mine), len(tests)), flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(mine))
    sys.exit(0 if result.wasSuccessful() else 1)
