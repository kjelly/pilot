import concurrent.futures, hashlib, json, os, pathlib, signal, subprocess, threading, time, urllib.request
B=pathlib.Path('/opt/issue236')
E=B/'evidence'; E.mkdir(exist_ok=True)
P=str(B/'pilot')
common=[P,'--services-dir',str(B/'services')]
results={}
def run(name,args,ok=True,timeout=360):
    t=time.monotonic()
    p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=timeout)
    (E/(name+'.log')).write_bytes(p.stdout)
    results[name]={'rc':p.returncode,'seconds':round(time.monotonic()-t,3)}
    if ok and p.returncode: raise RuntimeError(name+' failed; see raw log')
    return p
def save(): (E/'results.json').write_text(json.dumps(results,indent=2))
def identities():
    ids=subprocess.check_output(['docker','ps','-q']).decode().split()
    info=json.loads(subprocess.check_output(['docker','inspect',*ids]))
    return {x['Name']:{'id':x['Id'],'started':x['State']['StartedAt']} for x in info}
def snapshot():
    files=[B/'services/services.json']
    root=B/'services/cache'
    for rel in ['.pilot-services-owner.json','ca/ca.pem','ca/ca-key.pem','docker-compose.yml','harbor/harbor.yml','harbor/installer/docker-compose.yml','harbor/secrets/admin-password','harbor/secrets/database-password','pulp/admin.env','pulp/settings/settings.py','pulp/settings/secret-key']:
        files.append(root/rel)
    return {str(f.relative_to(B)):{'hash':hashlib.sha256(f.read_bytes()).hexdigest(),'mtime':f.stat().st_mtime_ns} for f in files}
stop=threading.Event(); requests=[]
def fetch():
    try:
        with urllib.request.urlopen('http://192.168.123.1:3142/archive.ubuntu.com/ubuntu/dists/noble/Release',timeout=8) as r:
            data=r.read(); assert len(data)>1000
            return r.status,hashlib.sha256(data).hexdigest()
    except Exception as e: return 0,type(e).__name__
def loop():
    while not stop.is_set(): requests.append(fetch()); stop.wait(.5)
try:
    baseline=fetch(); assert baseline[0]==200,baseline
    before=identities(); files=snapshot()
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        jobs=[pool.submit(run,'attach-'+str(i),common+['--data-dir',str(B/('agent-'+str(i))),'services','up']) for i in range(2)]
        for j in jobs:j.result()
    assert identities()==before,'container changed on healthy attach'
    assert snapshot()==files,'files changed on healthy attach'
    results['healthy_attach']={'containers':len(before),'identities_unchanged':True,'files_unchanged':True}
    thread=threading.Thread(target=loop);thread.start()
    for n in ['consumer-a','consumer-b']:
        run('vm-up-'+n,common+['--data-dir',str(B/n),'vm-target','up','--name','i236-'+n,'--base-image',str(B/'images/ubuntu-24.04-golden.qcow2'),'--memory','1024','--vcpus','1','--disk','8','--services','dev-lite'],timeout=420)
        run('inventory-'+n,common+['--data-dir',str(B/n),'vm-target','show-inventory','--name','i236-'+n])
    p=run('consumers-two',common+['services','consumers']); assert len(json.loads(p.stdout))==2
    for command,extra in [('down',[]),('purge',['--confirm']),('repair',[])]:
        p=run('refuse-'+command,common+['services',command,*extra],ok=False)
        assert p.returncode!=0 and b'consumer' in p.stdout.lower(),command
    run('vm-down-a',common+['--data-dir',str(B/'consumer-a'),'vm-target','down','--name','i236-consumer-a'])
    p=run('consumers-one',common+['services','consumers']);assert len(json.loads(p.stdout))==1
    p=run('surviving-guest-cache-request',common+['--data-dir',str(B/'consumer-b'),'vm-target','exec','--name','i236-consumer-b','--','sh','-c','curl --fail --max-time 20 --proxy http://192.168.123.1:3142 --output /tmp/issue236-release http://archive.ubuntu.com/ubuntu/dists/noble/Release && sha256sum /tmp/issue236-release'])
    assert baseline[1].encode() in p.stdout,'surviving guest response hash absent'
    run('attach-with-consumer',common+['services','up'])
    assert identities()==before,'container changed while attached guests active'
    run('vm-down-b',common+['--data-dir',str(B/'consumer-b'),'vm-target','down','--name','i236-consumer-b'])
    assert identities()==before,'container changed on final guest teardown'
    stop.set();thread.join()
    assert requests and all(x==baseline for x in requests),'cache continuity failed'
    results['continuity']={'requests':len(requests),'failures':0,'response_hash':baseline[1],'container_identities_unchanged':True}
    # Native lock-holder death and CLI cancellation, using the actual fixed UID lock.
    holder=subprocess.Popen(['python3','-c','import fcntl,time; f=open("/tmp/pilot-services-compose-0.lock","a"); fcntl.flock(f,fcntl.LOCK_EX); print("ready",flush=True); time.sleep(60)'],stdout=subprocess.PIPE)
    assert holder.stdout.readline().strip()==b'ready'
    waiter=subprocess.Popen(common+['services','up'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    time.sleep(.3);waiter.send_signal(signal.SIGTERM)
    out=waiter.communicate(timeout=5)[0];(E/'cancel-waiter.log').write_bytes(out)
    assert waiter.returncode!=0
    holder.kill();holder.wait()
    run('attach-after-holder-kill',common+['services','up'])
    results['native_lock']={'cancel_rc':waiter.returncode,'holder_killed_reacquired':True}
    results['status']='pass'
except Exception as e:
    results['status']='blocked';results['error']=str(e);raise
finally:
    stop.set()
    save()
