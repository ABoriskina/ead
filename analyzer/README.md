# BEFORE START
Необходимо виртуальное окружение и библиотеки, выполнять из корня проекта:
```
python3 -m venv .venv
source .venv/bin/activate
pip install prometheus-client
pip install black
pip install pyvis
pip install networkx
```

# Формат событий
Для удобства взят формат EVE JSON. Анализатор обрабатывает ляет события формата:
```
{
  "timestamp": "",
  "event_type": "",
  "sensor": "ebpf-anomaly-detector",
  "host": "",
  "proto": "",
  "src_ip": "",
  "src_port": ,
  "dest_ip": "",
  "dest_port": ,
  "process": {
    "pid": ,
    "comm": "",
    "uid": 
  },
  "flow": {
    "state": "",
    "direction": ""
  }
}
```

# Сеть
| Порт | Что на нём | Кто подключается |
| -- | -- | -- |
| 5000| server.py | client.py |
| 9000 | analyzer.py слушает | agent |
| 9200 | analyzer.py отдаёт метрики | prometheus |
| 9090 | web интерфейс и API prometheus | grafana |
| 3001 | web интерфейс grafana |  |


| Сервис | Адрес |
| -- | -- |
| Grafana | http://localhost:3001 |
| Prometheus | http://localhost:9090 |
| analyzer.py | http://localhost:9200 |
| web | http://localhost:8080 |


# Описание
Запускается два потока - correlation_worker и handle_agent. Handle agent запускается по потоку на каждого агента, отправляет полученные данные в общую очередь, откуда читает correlation worker.
