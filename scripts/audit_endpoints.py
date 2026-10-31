import ast
import json

with open('app.py', 'r', encoding='utf-8') as f:
    text = f.read()

tree = ast.parse(text)
endpoints_info = []

for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef):
        for dec in node.decorator_list:
            if isinstance(dec, ast.Call) and getattr(dec.func, 'attr', None) == 'route':
                route_path = dec.args[0].value if dec.args and isinstance(dec.args[0], ast.Constant) else 'unknown'
                methods = ['GET']
                for kw in dec.keywords:
                    if kw.arg == 'methods' and isinstance(kw.value, ast.List):
                        methods = [elt.value for elt in kw.value.elts if isinstance(elt, ast.Constant)]
                
                body_lines = text.splitlines()[node.lineno-1:node.end_lineno]
                body_text = '\n'.join(body_lines)
                
                auth = ('not in session' in body_text)
                admin = ('is_admin' in body_text)
                mongo_access = any(c in body_text for c in ['users.', 'posts.', 'comments.', 'jobs.'])
                ai_access = ('ai_service' in body_text or 'client.chat' in body_text)
                
                ext_services = []
                if 'send_email' in body_text or 'requests.' in body_text:
                    ext_services.append('Email/HTTP')
                if ai_access:
                    ext_services.append('AI Service')
                
                header_lines = '\n'.join(text.splitlines()[max(0, node.lineno-6):node.lineno])
                csrf_ex = ('@csrf.exempt' in header_lines)
                
                endpoints_info.append({
                    'line': node.lineno,
                    'path': route_path,
                    'methods': methods,
                    'func': node.name,
                    'auth': auth,
                    'admin': admin,
                    'mongo': mongo_access,
                    'ai': ai_access,
                    'csrf_exempt': csrf_ex,
                    'ext': ext_services
                })

endpoints_info.sort(key=lambda x: x['line'])
print(f"Total endpoints: {len(endpoints_info)}")
for ep in endpoints_info:
    m = str(ep['methods'])
    p = ep['path']
    fn = ep['func']
    au = str(ep['auth'])
    ad = str(ep['admin'])
    cs = str(ep['csrf_exempt'])
    mo = str(ep['mongo'])
    ai = str(ep['ai'])
    ex = str(ep['ext'])
    print(f"L{ep['line']:4d} | {m:16s} | {p:32s} | {fn:18s} | Auth:{au:5s} | Admin:{ad:5s} | CSRF_Ex:{cs:5s} | Mongo:{mo:5s} | AI:{ai:5s} | Ext:{ex}")

with open('endpoints_audit.json', 'w', encoding='utf-8') as f:
    json.dump(endpoints_info, f, indent=2)
