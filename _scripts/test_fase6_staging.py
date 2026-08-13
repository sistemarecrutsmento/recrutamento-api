import json,urllib.request,urllib.error,uuid,datetime
API=__import__('os').environ.get('API_URL','https://vagasio-api-staging.onrender.com');u=uuid.uuid4().hex[:8]
def req(method,path,b=None,t=None):
 d=json.dumps(b).encode() if b is not None else None;h={'Content-Type':'application/json'}
 if t:h['Authorization']='Bearer '+t
 try:
  r=urllib.request.urlopen(urllib.request.Request(API+path,data=d,headers=h,method=method),timeout=50);return r.status,json.loads(r.read() or b'{}')
 except urllib.error.HTTPError as e:
  try:return e.code,json.loads(e.read() or b'{}')
  except:return e.code,{}
def post(p,b,t=None):return req('POST',p,b,t)
def put(p,b,t=None):return req('PUT',p,b,t)
e=post('/api/empresa/cadastro',{'empresa_nome':'F6 Empresa '+u,'admin_nome':'Admin','admin_email':'f6a'+u+'@example.test','email_principal':'f6a'+u+'@example.test','admin_senha':'Teste12345!'});te=e[1]['token'];v=post('/api/empresa/vagas',{'titulo':'F6 Vaga '+u,'cidade':'SP','estado':'SP','area':'Tecnologia','etapas':[{'nome':'Inscrição'},{'nome':'Triagem'},{'nome':'Entrevista RH'},{'nome':'Entrevista Gestor'}]},te);vid=v[1]['vaga']['id'];c=post('/api/candidato/cadastro',{'nome':'F6 Candidate '+u,'email':'f6c'+u+'@example.test','senha':'Teste12345!'});tc=c[1]['token'];ap=post(f'/api/candidato/candidatar/{vid}',{},tc);cid=ap[1].get('candidatura',{}).get('id') or ap[1].get('candidatura_id');
# create a presencial interview, avoiding external video provider in controlled staging
future=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=2)).isoformat();schedule=post('/api/empresa/entrevista',{'candidatura_id':cid,'etapa':3,'data_hora':future,'duracao_minutos':45,'local':'Sala 1','observacoes':'Teste F6','entrevistadores':[{'nome':'Maria RH','email':'maria@example.test','papel':'RH'},{'nome':'João Gestor','email':'joao@example.test','papel':'Gestor'}]},te);iid=schedule[1].get('id') or schedule[1].get('entrevista',{}).get('id');agenda=req('GET','/api/empresa/agenda?periodo=proximos',t=te);candviews=req('GET','/api/candidato/entrevistas',t=tc);reschedule=put(f'/api/empresa/entrevista/{iid}',{'data_hora':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=3)).isoformat(),'local':'Sala 2'},te);nosh=put(f'/api/empresa/entrevista/{iid}',{'status':'no-show'},te);cancel=post(f'/api/empresa/entrevista/{iid}/cancelar',{'motivo':'cancelamento de teste'},te);cross=put(f'/api/empresa/entrevista/{iid}',{'local':'vazamento'},'invalid')
print(json.dumps({'apply':ap[0],'schedule':schedule[0],'interviewers_count':len(schedule[1].get('entrevista',{}).get('entrevistadores',[])),'interview_id':iid,'agenda':agenda[0],'candidate_interviews':candviews[0],'reschedule':reschedule[0],'no_show':nosh[0],'cancel':cancel[0],'invalid_auth':cross[0]},ensure_ascii=False))
