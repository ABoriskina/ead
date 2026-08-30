package main

const indexHTML = `<!doctype html>
<html lang="ru">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">

    <title>Консоль EAD</title>
    <link rel="icon" href="/static/favicon.ico" sizes="any">

    <style>
    @font-face {
      font-family: "Montserrat";
      src: url("/static/fonts/Montserrat-Medium.ttf") format("truetype");
      font-weight: 500;
      font-style: normal;
      font-display: swap;
    }

    @font-face {
      font-family: "Montserrat";
      src: url("/static/fonts/Montserrat-Black.ttf") format("truetype");
      font-weight: 900;
      font-style: normal;
      font-display: swap;
    }

:root
      {
        color-scheme:dark;
        font-family: "Montserrat", Arial, sans-serif;
        font-weight:500;
        background:#102232;
        color:#ff751f
      }
      body{
        margin:0;
        padding:24px
      }
      .brand {
        display: flex;
        align-items: center;
        gap: 48px;
        padding: 12px 24px 12px 12px;
        background: #27303a;
        border: 1px solid #3a4652;
        border-radius: 20px;
        margin-bottom: 40px;
      }
      .brand-icon{
        width:128px;
        height:128px;
        object-fit: contain;
        flex:0 0 auto
      }
      h1{
        font-size:38px;
        font-weight:500;
        letter-spacing:2px;
        margin:0
      }
      .agent-status {
        display: flex;
        align-items: center;
        gap: 10px;
        margin-left: 10px;
        margin-bottom: 40px;
        font-size: 16px;
        font-weight: 500;
      }
      .status-indicator {
        width: 10px;
        height: 10px;
        margin-left: 20px;
        border-radius: 50%;
        background: #999;
      }
      .status-indicator.connected {
        background: #7ee787;
        box-shadow: 0 0 8px rgba(126, 231, 135, 0.7);
      }
      .status-indicator.disconnected {
        background: #ff7b72;
        box-shadow: 0 0 8px rgba(255, 123, 114, 0.7);
      }
      .alert-counter {
        display: flex;
        align-items: center;
        gap: 16px;
        width: fit-content;
        max-width: 100%;
        box-sizing: border-box;
        padding: 12px 20px;
        background: #27303a;
        border: 1px solid #3a4652;
        border-radius: 16px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.25);
        font-size: 20px;
        font-weight: 500;
        margin-bottom: 18px;
      }
      .count {
        font-size: 32px;
        font-weight: 500;
        color: #ad1029;
      }
      .grid{
        display:grid;
        grid-template-columns:1fr 1fr;
        gap:16px;
        margin-top:18px
      }
      .panel{
        background:#27303a;
        border:1px solid #333;
        border-radius:8px;
        padding:14px
      }
      h2{
        font-size:18px;
        font-weight:500;
        margin:0 0 10px
      }
      textarea{
        font:inherit;
        box-sizing:border-box;
        width:100%;
        height:430px;
        background:#1d242b;
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
        font:inherit;
        margin-top:9px;
        background:#ff751f;
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

    <header class="brand">
      <img class="brand-icon" src="/static/logo.png" alt="EAD">
      <h1>Консоль eBPF anomaly detector</h1>
    </header>

    <div class="agent-status">
      <span class="status-indicator" id="agent-indicator"></span>
      <span id="agent-status">проверка агента…</span>
    </div>

    <div class="alert-counter">
      <span>Алертов всего:</span>
      <span class="count" id="count">—</span>
    </div>

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
      <h2>События, вызвавшие алерт:</h2>
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

    async function updateAgentStatus() {
      let text = document.getElementById('agent-status');
      let indicator = document.getElementById('agent-indicator');
      try {
          let response = await fetch('/api/agent/status');
          if (!response.ok) {
              throw new Error(await response.text());
          }

          let status = await response.json();
          if (status.connected) {
              text.textContent = 'Агент подключён';
              indicator.className =
                  'status-indicator connected';
          } else {
              text.textContent = 'Агент отключён';
              indicator.className =
                  'status-indicator disconnected';
          }
      } catch (error) {
          text.textContent = 'Анализатор недоступен';
          indicator.className =
              'status-indicator disconnected';
      }
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
    updateAgentStatus();
    setInterval(updateAgentStatus, 2000);
		let events=new EventSource('/api/alerts');
		events.onmessage=e=>show(e.data);

    </script>
  </body>
</html>`
