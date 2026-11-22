"""Positive package propagation check, strict policy, two loopback-only nc28 nodes."""
from pathlib import Path
from decimal import Decimal
from hashlib import sha256
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from coincurve import PrivateKey

import argparse
options=argparse.ArgumentParser(description=__doc__)
options.add_argument('--bin-dir',required=True,type=Path,help='directory containing nc28.0 namecoind and namecoin-cli')
options.add_argument('--framework-dir',required=True,type=Path,help='upstream nc28.0 test/functional directory containing test_framework/')
options.add_argument('--output-dir',required=True,type=Path,help='fresh or task-owned output directory for logs and ephemeral node data')
arg=options.parse_args()
evidence=arg.output_dir.expanduser().resolve()
evidence.mkdir(parents=True,exist_ok=True)
base=evidence
(base/'tmp').mkdir(exist_ok=True)
bin_dir=arg.bin_dir.expanduser().resolve(strict=True)
sys.path.insert(0,str(arg.framework_dir.expanduser().resolve(strict=True)))
from test_framework.messages import CTransaction,CTxIn,CTxOut,COutPoint,CTxInWitness
from test_framework.script import SegwitV0SignatureHash,hash160
dirs=[Path(tempfile.mkdtemp(prefix='p2a-loopback-',dir=base/'tmp')).resolve() for _ in range(2)]
sockets=[socket.socket() for _ in range(4)]
for s in sockets:s.bind(('127.0.0.1',0))
ports=[s.getsockname()[1] for s in sockets]
for s in sockets:s.close()
processes=[]
def rpc(i,method,*args,wait=False):
    cmd=[str(bin_dir/'namecoin-cli'),'-regtest','-datadir='+str(dirs[i]),'-rpcport='+str(ports[i]),'-rpcconnect=127.0.0.1','-stdin']+(['-rpcwait','-rpcwaittimeout=20'] if wait else [])+[method]
    values=[v if isinstance(v,str) else json.dumps(v,separators=(',',':')) for v in args]
    p=subprocess.run(cmd,input='\n'.join(values)+('\n' if values else ''),text=True,capture_output=True,timeout=30)
    if p.returncode:raise RuntimeError(method+' '+p.stderr[:340])
    val=p.stdout.strip()
    if not val:return None
    try:return json.loads(val)
    except ValueError:return val
def until(pred,limit=50):
    start=time.monotonic()
    while time.monotonic()-start<limit:
        if pred():return True
        time.sleep(.25)
    return False
def pk(k):return k.public_key.format(compressed=True)
def pkh(k):return b'\x00\x14'+hash160(pk(k))
def tx(inputs,outputs,version=2):
    t=CTransaction();t.version=version
    t.vin=[CTxIn(COutPoint(int(tid,16),index),b'',0xfffffffd) for tid,index,_,_ in inputs]
    t.vout=[CTxOut(amount,script) for amount,script in outputs]
    t.wit.vtxinwit=[]
    for index,(_,__,amount,k) in enumerate(inputs):
        wi=CTxInWitness()
        if k is not None:
            digest=SegwitV0SignatureHash(bytes.fromhex('76a914')+hash160(pk(k))+bytes.fromhex('88ac'),t,index,1,amount)
            wi.scriptWitness.stack=[k.sign(digest,hasher=None)+b'\x01',pk(k)]
        t.wit.vtxinwit.append(wi)
    t.rehash()
    return t.hash,t.serialize_with_witness().hex()
result={'profile':'independent 1-parent / 1-child P2A relay positive control','chain':'regtest','peers':'two fresh Namecoin Core 28, distinct local data directories, one loopback connection, no other peers'}
try:
    for i in range(2):
        cmd=[str(bin_dir/'namecoind'),'-regtest','-datadir='+str(dirs[i]),'-rpcport='+str(ports[i]),'-port='+str(ports[2+i]),'-server=1','-rpcbind=127.0.0.1','-rpcallowip=127.0.0.1','-listen=1','-bind=127.0.0.1:'+str(ports[2+i]),'-listenonion=0','-onion=0','-onlynet=ipv4','-connect=0','-dnsseed=0','-fixedseeds=0','-discover=0','-disablewallet=1','-acceptnonstdtxn=0','-printtoconsole=0','-par=2']
        processes.append(subprocess.Popen(cmd,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
    (evidence/'p2a-peer-pids.log').write_text(' '.join(str(p.pid) for p in processes)+'\n')
    for i in range(2):assert rpc(i,'getblockchaininfo',wait=True)['chain']=='regtest'
    rpc(1,'addnode',f'127.0.0.1:{ports[2]}','onetry')
    assert until(lambda:all(len(rpc(i,'getpeerinfo'))==1 and rpc(i,'getpeerinfo')[0]['version']>0 for i in range(2)),15)
    result['ordinary_peer_connected']=True
    fund=PrivateKey(); disposable=PrivateKey()
    desc=rpc(0,'getdescriptorinfo','wpkh('+pk(fund).hex()+')')['descriptor']
    addr=rpc(0,'deriveaddresses',desc)[0]
    blocks=rpc(0,'generatetoaddress',105,addr)
    assert until(lambda:rpc(1,'getbestblockhash')==blocks[-1])
    def funding(i):
        cb=rpc(0,'getblock',blocks[i],2)['tx'][0]
        out=next(x for x in cb['vout'] if x['scriptPubKey'].get('address')==addr)
        return cb['txid'],out['n'],int(Decimal(str(out['value']))*100_000_000),fund
    c1=funding(0);c2=funding(1)
    s_id,setup=tx([c1],[(1500000,pkh(disposable)),(c1[2]-2000000,pkh(fund))])
    rpc(0,'sendrawtransaction',setup)
    result['ordinary_tx_seen_by_peer_before_mining']=until(lambda:s_id in rpc(1,'getrawmempool'))
    assert result['ordinary_tx_seen_by_peer_before_mining']
    funding_tip=rpc(0,'generatetoaddress',1,addr)[0]
    assert until(lambda:rpc(1,'getbestblockhash')==funding_tip)
    parent_id,parent=tx([(s_id,0,1500000,disposable)],[(1400000,pkh(fund)),(100000,bytes.fromhex('51024e73'))],3)
    del disposable
    child_id,child=tx([(parent_id,1,100000,None),c2],[(c2[2]+100000-500000,pkh(fund))],3)
    alone=rpc(0,'testmempoolaccept',[parent])[0]
    result.update(parent_alone_admitted=alone['allowed'],parent_alone_reason=alone.get('reject-reason'),version=3,parent_fee_sat=0,child_fee_sat=500000,p2a_value_sat=100000)
    submitted=rpc(0,'submitpackage',[parent,child])
    result['source_submitpackage']=submitted['package_msg']
    assert {parent_id,child_id}<=set(rpc(0,'getrawmempool'))
    result['peer_saw_both_before_block']=until(lambda:{parent_id,child_id}<=set(rpc(1,'getrawmempool')),50)
    result['peer_mempool_size_at_observation']=len(rpc(1,'getrawmempool'))
    tip=rpc(0,'generatetoaddress',1,addr)[0]
    assert until(lambda:rpc(1,'getbestblockhash')==tip)
    result['both_confirmed_at_peer']= {parent_id,child_id}<=set(rpc(1,'getblock',tip,1)['tx'])
    result['peer_received_no_rpc_submission']=True
    assert not result['parent_alone_admitted'] and result['parent_alone_reason']=='min relay fee not met', 'standalone control did not produce the expected fee rejection'
    assert result['source_submitpackage']=='success', 'local package submission did not succeed'
    assert result['peer_saw_both_before_block'], 'the second peer did not observe the full package in its mempool before mining'
    assert result['both_confirmed_at_peer'], 'both package transactions must confirm on the second node'
    print(json.dumps(result,indent=2),flush=True)
finally:
    for i,p in enumerate(processes):
        if p.poll() is None:
            try:rpc(i,'stop')
            except Exception:p.terminate()
    for p in processes:
        try:p.wait(10)
        except subprocess.TimeoutExpired:
            p.terminate()
            try:p.wait(5)
            except subprocess.TimeoutExpired:p.kill();p.wait()
    result['stopped_all_owned_processes']=all(p.poll() is not None for p in processes)
    (evidence/'p2a-peers-01.json').write_text(json.dumps(result,indent=2)+'\n')
    for d in dirs:
        assert d.parent==(base/'tmp').resolve();shutil.rmtree(d)
