
import re




eff = {}


max_ordn = 0

ef = open("sys_effects.h" , "w")

ef.write("#ifndef __EFFECT_H_H\n")
ef.write("#define __EFFECT_H_H\n")


for line in open("linux_x86_syscalls_effects"):
    print line
    foo = re.search("^#", line)
    if foo:
        continue
    foo = re.search("^\s*$", line)
    if foo:
        continue    
    parts = line.split()
    labels = []
    ordn = None
    while True:
        part = parts[0]
        if ordn is None:
            foo = re.search("^[A-Z][A-Z]$", part)
            if foo:
                labels.append(part)
            else:
                foo = re.search("^[0-9]+$", part)
                if foo:
                    ordn = int(part)
                else:
                    kjsdhfsdjf
        else:
            # find the syscall name
            done = False
            while (not done):
                foo = re.search("^([^(]+)\(", part)
                if foo:
                    scname = foo.groups()[0]
                    done = True
                    break
                parts = parts[1:]
                part = parts[0]
            assert (done == True)
            break
        parts = parts[1:]
    eff[ordn] =  (" ".join(labels)) + " " + scname
    max_ordn = max(ordn, max_ordn)


ef.write("const char * sys_effect[] = {\n")

for i in range(0,max_ordn+1):
    if not (i in eff):
        eff[i] = "ZZ"
    ef.write( '\"%s\",\n' % eff[i])
    

ef.write( "};\n" )

ef.write("#endif\n")

ef.close()

