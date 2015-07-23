#!/usr/bin/python3

from __future__ import print_function
import string, os, sys, platform

os.system('rm -rf testing-flags')
os.mkdir('testing-flags');
with open('testing-flags/test.c', 'w') as f:
    f.write("""int main() {
  return 0;
}
""")

# add , '-fprofile-arcs', '-ftest-coverage' to both of the following
# lines in order to enable gcov coverage testing
optional_flags = ['-Wall', '-Werror', '-O2', '-g']
optional_linkflags = ['-lprofiler']

possible_flags = ['-std=c11', '-std=c99', '-flto']
possible_linkflags = ['-flto']

if os.getenv('MINIMAL') == None:
    print('# We are not minimal')
    possible_flags += optional_flags
    possible_linkflags += optional_linkflags

if os.getenv('MINIMAL') == None:
    print('# We are not minimal')
    config = {'cc': os.getenv('CC', 'gcc'),
                'flags': [os.getenv('CFLAGS', '')],
                'linkflags': [os.getenv('LDFLAGS', '')],
                'os': platform.system().lower(),
                'arch': platform.machine()}
else:
    print('# We are minimal')
    possible_flags.remove('-std=c11')
    cc = os.getenv('CC', 'oopsies')
    config = {'cc': os.getenv('CC', '${CC-gcc}'),
              'flags': [os.getenv('CFLAGS', '${CFLAGS-} -Ibigbro')],
              'linkflags': [os.getenv('LDFLAGS', '${LDFLAGS-} -Lbigbro')],
              'os': platform.system().lower(),
              'arch': platform.machine()}

def compile_works(flags):
    return not os.system('%s %s -c -o testing-flags/test.o testing-flags/test.c' % (cc, ' '.join(flags)))
def link_works(flags):
    cmd = '%s -o testing-flags/test testing-flags/test.c %s' % (cc, ' '.join(flags))
    print('# trying', cmd, file=sys.stdout)
    return not os.system(cmd)

cc = config['cc']
flags = config['flags']
linkflags = config['linkflags']

if not compile_works(flags):
    print('# unable to compile using %s %s -c test.c' % (cc, flags))
    exit(0)
if not link_works(linkflags):
    print('# unable to link using %s %s -o test test.c\n' % (cc, ' '.join(linkflags)))
    exit(0)

for flag in possible_flags:
    if compile_works(flags+[flag]):
        flags += [flag]
    else:
        print('# %s cannot use flag:' % (cc), flag)
if len(flags) > 0 and flags[0] == ' ':
    flags = flags[1:]
for flag in possible_linkflags:
    if link_works(linkflags + [flag]):
        linkflags += [flag]
    else:
        print('# %s linking cannot use flag:' % (cc), flag)

if '-std=c11' in flags:
    flags = [f for f in flags if f != '-std=c99']
linkflags = list(filter(None, linkflags))
flags = list(filter(None, flags))

config['flags'] = flags
config['linkflags'] = linkflags

sources = ['tweetnacl', 'randombytes']

for s in sources:
    print('| cd src && %s %s -o %s.o -c %s.c' % (cc, ' '.join(flags), s, s))
    print('> src/%s.o' % (s))
    print()

ctests = ['null']

for test in ctests:
    print('| %s '%cc+' '.join(linkflags)+' -o tests/%s.test' % (test),
          'tests/%s.o' % (test),
          ' '.join(['src/%s.o' % (s) for s in sources]))
    print('> tests/%s.test' % (test))
    print('< tests/%s.o' % (test))
    for s in sources:
        print('< src/%s.o' % (s))
    print()

    print('| cd tests && %s %s -I../src -o %s.o -c %s.c'
          % (cc, ' '.join(flags), test, test))
    print('> tests/%s.o' % (test))
    print()

os.system('rm -rf testing-flags')