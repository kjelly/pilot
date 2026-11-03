import subprocess,json,pathlib,time,urllib.request
B=pathlib.Path('/opt/issue236'); E=B/'evidence'; C=[str(B/'pilot'),'--services-dir',str(B/'services')]; result={}
def run(name,args,ok=True):
 p=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=360);(E/(name+'.log')).write_bytes(p.stdout); result[name]=p.returncode
 if ok: assert p.returncode==0,name
 return p
try:
 run('pause-pulp',['docker','pause','pilot-services-dev-lite-pulp-1'])
 try:
  p=run('unhealthy-attach',C+['services','up'],False)
  assert p.returncode!=0
  assert b'repair' in p.stdout.lower()
  assert subprocess.check_output(['docker','inspect','--format','{{.State.Paused}}','pilot-services-dev-lite-pulp-1']).strip()==b'true'
 finally:run('unpause-pulp',['docker','unpause','pilot-services-dev-lite-pulp-1'])
 run('maintenance-down',C+['services','down'])
 run('maintenance-repair',C+['services','repair'])
 with urllib.request.urlopen('http://192.168.123.1:3142/archive.ubuntu.com/ubuntu/dists/noble/Release',timeout=15) as r:assert r.status==200
 result['status']='pass'
except Exception as e:result['status']='blocked';result['error']=str(e);raise
finally:(E/'maintenance-results.json').write_text(json.dumps(result,indent=2))
