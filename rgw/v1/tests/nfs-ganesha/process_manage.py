import psutil

process_name = "ganesha"

for p in psutil.process_iter():
    if process_name in p.name():
        print(("found process :%s and killing it" % p.name()))
        print(p.cmdline())
        print(p.name())
        p.kill()
        break
