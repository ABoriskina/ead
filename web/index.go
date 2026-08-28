package main

const indexHTML = `<!doctype html>
<html lang="ru">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">

    <title>Консоль EAD</title>

    <style>
:root
      {
        color-scheme:dark;
        font-family:ui-monospace,SFMono-Regular,Consolas,monospace;
        background:#111;
        color:#ffe100
      }
      body{
        margin:0;
        padding:24px
      }
      h1{
        font-size:25px;
        margin:0 0 20px
      }
      .count{
        font-size:32px;
        color:#ad1029
      }
      .grid{
        display:grid;
        grid-template-columns:1fr 1fr;
        gap:16px;
        margin-top:18px
      }
      .panel{
        background:#191919;
        border:1px solid #333;
        border-radius:8px;
        padding:14px
      }
      h2{
        font-size:15px;
        margin:0 0 10px
      }
      textarea{
        box-sizing:border-box;
        width:100%;
        height:430px;
        background:#0d0d0d;
        color:#ddd;
        border:1px solid #444;
        padding:12px;
        resize:vertical
      }
      textarea:focus {
		border-color: #905404;
		outline: none;
      }
      button{
        margin-top:9px;
        background:#ffe100;
        color:black;
        border:0;
        border-radius:5px;
        padding:8px 14px;
        cursor:pointer
      }
      .status{
        margin-left:10px;
        font-size:12px;
        color:#999
      }
	  .status-success{
		color: #7ee787;
	  }

	  .status-error{
		color: #ff7b72;
	  }
      pre{
        white-space:pre-wrap;
        word-break:break-word;
        border-bottom:1px solid #333;
        padding:10px 0;
        margin:0
      }
      .alerts{
        max-height:520px;
        overflow:auto
      }
      @media(max-width:850px){
        
        .grid{
          grid-template-columns:1fr
        }
      }
</style>
  </head>
  
  <body>

    <h1>Консоль eBPF anomaly detector</h1>
    <div>Алертов всего: <span class="count" id="count">—</span></div>
    <div class="grid">
      <section class="panel">
        <h2>correlation-config.json</h2>
        <textarea id="correlation"></textarea>
        <button onclick="save('correlation')">Сохранить и применить</button>
        <span class="status" id="correlation-status"></span>
      </section>
      <section class="panel">
        <h2>bpf-config.json</h2>
        <textarea id="bpf"></textarea>
        <button onclick="save('bpf')">Сохранить и применить</button>
        <span class="status" id="bpf-status"></span>
      </section>
    </div>
    <section class="panel" style="margin-top:16px">
      <h2>События, вызвавшие алерт</h2>
      <div class="alerts" id="alerts"></div>
    </section>

    <script>

		async function load(name)
		{
			let field=document.getElementById(name),status=document.getElementById(name+'-status');
			try {
				let r=await fetch('/api/config/'+name);
				if(!r.ok)
				throw new Error(await r.text());
				field.value=JSON.stringify(await r.json(),null,2);
				status.textContent='загружено'
				status.className = 'status status-success';
			}
			catch(error){
				status.textContent='ошибка: '+error.message
				status.className = 'status status-error';
			}
		}

		async function save(name){
			let s=document.getElementById(name+'-status');
			s.textContent='сохраняю…';
			let r=await fetch('/api/config/'+name,{method:'PUT',headers:{'Content-Type':'application/json'},body:document.getElementById(name).value});
			s.textContent=r.ok?'применено':await r.text()
		}

		async function count(){
			try{
				let r=await fetch('/api/alerts/count');
				if(r.ok)document.getElementById('count').textContent=(await r.json()).count}
			catch(_){}
		}

		function show(raw){
			let p=document.createElement('pre');
			try{
				p.textContent=JSON.stringify(JSON.parse(raw),null,2)
			}
			catch(_){
				p.textContent=raw
			}
			let box=document.getElementById('alerts');box.prepend(p)
		}

		load('correlation');
		load('bpf');
		count();
		setInterval(count,2000);
		let events=new EventSource('/api/alerts');
		events.onmessage=e=>show(e.data);

    </script>
  </body>
</html>`
